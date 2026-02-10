import {
  BookOpen,
  Shield,
  Search,
  Code2,
  BarChart3,
  Layers,
  Zap,
  Globe,
  ExternalLink,
} from "lucide-react";

const SECTIONS = [
  {
    id: "overview",
    icon: <Shield className="h-5 w-5" />,
    title: "Overview",
    content: `Sentinel Protocol is an AI-powered smart contract security auditor that combines:

• **LLM Analysis** — Groq's Llama 3.3 70B model performs deep code reasoning
• **RAG Pattern Matching** — 20+ known vulnerability patterns matched against your contract
• **On-Chain Data** — Alchemy RPC fetches verified source code, bytecode, and proxy info
• **Trust Scoring** — A weighted 0-100 score (Security 60%, Quality 20%, Verification 20%)

All of this runs in seconds with zero cost.`,
  },
  {
    id: "analyze-address",
    icon: <Search className="h-5 w-5" />,
    title: "Analyze by Address",
    content: `1. Go to the **Analyze** page
2. Select the blockchain network (Ethereum, Polygon, Arbitrum, or Base)
3. Paste the contract address (0x…)
4. Click **Analyze Contract**

The backend will:
- Fetch verified source code from the block explorer
- If unverified, fall back to bytecode decompilation
- Run the code through the LLM and RAG pipeline
- Return a full trust score, vulnerability list, and recommendations`,
  },
  {
    id: "analyze-source",
    icon: <Code2 className="h-5 w-5" />,
    title: "Analyze Source Code",
    content: `You can also paste raw Solidity source code directly:

1. Switch to the **Paste Source** tab on the Analyze page
2. Paste your .sol contract code
3. Click **Analyze Contract**

This is ideal for pre-deployment auditing — check your code before it goes on-chain.`,
  },
  {
    id: "trust-score",
    icon: <BarChart3 className="h-5 w-5" />,
    title: "Trust Score Explained",
    content: `The trust score is a composite 0-100 rating:

| Component | Weight | Description |
|-----------|--------|-------------|
| Security | 60% | Vulnerability severity & count |
| Code Quality | 20% | Code patterns, complexity |
| Verification | 20% | Source verified, proxy status |

**Risk Levels:**
- 80-100: **Safe** (green)
- 60-79: **Medium Risk** (yellow)  
- 40-59: **High Risk** (orange)
- 0-39: **Critical Risk** (red)`,
  },
  {
    id: "networks",
    icon: <Globe className="h-5 w-5" />,
    title: "Supported Networks",
    content: `Sentinel Protocol supports the following EVM chains:

- **Ethereum** — Mainnet via Alchemy RPC
- **Polygon** — Polygon PoS via Alchemy  
- **Arbitrum** — Arbitrum One via Alchemy
- **Base** — Base Mainnet via Alchemy

Each network uses the corresponding block explorer API for source code verification.`,
  },
  {
    id: "api",
    icon: <Zap className="h-5 w-5" />,
    title: "API Reference",
    content: `The backend exposes a REST API at \`/api/v1\`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| /analyze | POST | Analyze contract by address |
| /analyze/source | POST | Analyze raw source code |
| /health | GET | Service health check |
| /networks | GET | List supported networks |
| /history | GET | Recent analysis history |
| /stats | GET | Aggregate statistics |
| /validate/{address} | GET | Validate an address |

Full Swagger docs available at \`/docs\` on the backend.`,
  },
  {
    id: "architecture",
    icon: <Layers className="h-5 w-5" />,
    title: "Architecture",
    content: `**Frontend:** Next.js 16 + TypeScript + Tailwind CSS v4
**Backend:** Python FastAPI
**Database:** Neon PostgreSQL (serverless)
**LLM:** Groq Cloud (Llama 3.3 70B)
**Blockchain:** Alchemy RPC (multi-chain)
**Vector Store:** In-memory pattern matching

The analysis pipeline:
1. Fetch contract data from blockchain
2. Match against vulnerability patterns (RAG)
3. Run LLM analysis on source/bytecode
4. Calculate weighted trust score
5. Store results and return report`,
  },
];

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
      <div className="mb-10">
        <h1 className="flex items-center gap-2 text-3xl font-bold">
          <BookOpen className="h-7 w-7 text-accent" />
          Documentation
        </h1>
        <p className="mt-2 text-muted">
          Learn how Sentinel Protocol works and how to use it
        </p>
      </div>

      {/* Table of Contents */}
      <nav className="mb-10 rounded-xl border border-card-border bg-card p-5">
        <h2 className="mb-3 text-sm font-semibold text-muted uppercase tracking-wider">
          Contents
        </h2>
        <ul className="space-y-1.5">
          {SECTIONS.map((s) => (
            <li key={s.id}>
              <a
                href={`#${s.id}`}
                className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm text-muted hover:text-foreground hover:bg-white/5 transition-colors"
              >
                {s.icon}
                {s.title}
              </a>
            </li>
          ))}
        </ul>
      </nav>

      {/* Sections */}
      <div className="space-y-10">
        {SECTIONS.map((s) => (
          <section
            key={s.id}
            id={s.id}
            className="rounded-xl border border-card-border bg-card p-6 scroll-mt-24"
          >
            <h2 className="flex items-center gap-2 text-xl font-semibold mb-4">
              <span className="text-accent">{s.icon}</span>
              {s.title}
            </h2>
            <div className="prose prose-invert prose-sm max-w-none text-foreground/80 leading-relaxed whitespace-pre-line">
              {s.content}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

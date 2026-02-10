import Link from "next/link";
import {
  Shield,
  Search,
  Brain,
  Layers,
  ArrowRight,
  ShieldCheck,
  Zap,
  Globe,
} from "lucide-react";

const FEATURES = [
  {
    icon: <Brain className="h-6 w-6" />,
    title: "AI-Powered Analysis",
    desc: "Groq LLM (Llama 3.3 70B) performs deep code reasoning to surface vulnerabilities human auditors might miss.",
  },
  {
    icon: <ShieldCheck className="h-6 w-6" />,
    title: "Trust Score",
    desc: "Weighted 0-100 score combining security, code quality, and verification metrics in one glance.",
  },
  {
    icon: <Layers className="h-6 w-6" />,
    title: "Multi-Chain",
    desc: "Supports Ethereum, Polygon, Arbitrum, and Base with automatic proxy detection and source fetching.",
  },
  {
    icon: <Zap className="h-6 w-6" />,
    title: "Instant Results",
    desc: "Get a full security audit in seconds — no wallet connection or payment required.",
  },
  {
    icon: <Globe className="h-6 w-6" />,
    title: "RAG Pattern Matching",
    desc: "20+ vulnerability patterns matched against your contract using retrieval-augmented generation.",
  },
  {
    icon: <Search className="h-6 w-6" />,
    title: "Bytecode Fallback",
    desc: "Even unverified contracts get analyzed through decompiled bytecode heuristics.",
  },
];

export default function HomePage() {
  return (
    <div className="gradient-bg">
      {/* Hero */}
      <section className="mx-auto max-w-7xl px-4 pt-24 pb-16 sm:px-6 lg:px-8 text-center">
        <div className="inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-4 py-1.5 text-xs font-medium text-accent mb-6">
          <Shield className="h-3.5 w-3.5" />
          AI-Powered Smart Contract Auditor
        </div>

        <h1 className="text-4xl font-extrabold tracking-tight sm:text-6xl lg:text-7xl">
          Secure your contracts
          <br />
          <span className="text-accent">before deployment</span>
        </h1>

        <p className="mx-auto mt-6 max-w-2xl text-lg text-muted">
          Sentinel Protocol combines LLM reasoning, pattern matching, and
          on-chain data to deliver instant, comprehensive smart contract
          security audits — completely free.
        </p>

        <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/analyze"
            className="inline-flex items-center gap-2 rounded-xl bg-accent px-6 py-3.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
          >
            Start Free Audit <ArrowRight className="h-4 w-4" />
          </Link>
          <Link
            href="/docs"
            className="inline-flex items-center gap-2 rounded-xl border border-card-border bg-card px-6 py-3.5 text-sm font-semibold text-foreground transition-colors hover:bg-white/5"
          >
            Read the Docs
          </Link>
        </div>
      </section>

      {/* Feature Grid */}
      <section className="mx-auto max-w-7xl px-4 py-20 sm:px-6 lg:px-8">
        <h2 className="text-center text-2xl font-bold sm:text-3xl">
          Everything you need for contract security
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-center text-muted">
          A full audit pipeline — from source fetching to AI analysis —
          packaged in one fast, free tool.
        </p>

        <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="group rounded-2xl border border-card-border bg-card p-6 transition-all hover:border-accent/40"
            >
              <div className="mb-4 inline-flex rounded-lg bg-accent/15 p-2.5 text-accent">
                {f.icon}
              </div>
              <h3 className="text-lg font-semibold">{f.title}</h3>
              <p className="mt-2 text-sm text-muted leading-relaxed">
                {f.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* CTA Banner */}
      <section className="mx-auto max-w-7xl px-4 pb-24 sm:px-6 lg:px-8">
        <div className="rounded-2xl border border-accent/30 bg-accent/5 p-10 text-center">
          <h2 className="text-2xl font-bold sm:text-3xl">
            Ready to audit your contract?
          </h2>
          <p className="mx-auto mt-3 max-w-md text-muted">
            Paste an address or source code and get a complete security report
            in under 30 seconds.
          </p>
          <Link
            href="/analyze"
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-accent px-6 py-3 text-sm font-semibold text-white hover:bg-accent-hover"
          >
            Analyze Now <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </div>
  );
}

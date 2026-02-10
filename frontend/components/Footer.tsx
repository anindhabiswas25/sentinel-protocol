import { Shield } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-card-border bg-background py-8">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center gap-4 sm:flex-row sm:justify-between">
          <div className="flex items-center gap-2 text-sm text-muted">
            <Shield className="h-4 w-4 text-accent" />
            <span>Sentinel Protocol &copy; {new Date().getFullYear()}</span>
          </div>
          <p className="text-xs text-muted/60">
            AI-powered smart contract security &middot; Built for hackathon
          </p>
        </div>
      </div>
    </footer>
  );
}

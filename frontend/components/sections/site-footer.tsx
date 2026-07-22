import { ExternalLink } from "lucide-react";

import { BUILT_FOR_TAG, REPO_URL, TEAM_CREDITS } from "@/lib/constants";

export function SiteFooter() {
  return (
    <footer className="relative border-t border-border px-6 py-12">
      <div className="mx-auto flex max-w-6xl flex-col items-center gap-6 text-center sm:flex-row sm:items-start sm:justify-between sm:text-left">
        <div>
          <p className="text-sm font-medium text-foreground">
            Quantum-Secured Threat Intelligence Pipeline
          </p>
          <ul className="mt-3 space-y-1 text-sm text-muted-foreground">
            {TEAM_CREDITS.map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </div>

        <div className="flex flex-col items-center gap-4 sm:items-end">
          <a
            href={REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            <ExternalLink className="h-4 w-4" />
            Repository
          </a>
          <span className="font-mono text-xs text-muted-foreground/70">
            {BUILT_FOR_TAG}
          </span>
        </div>
      </div>
    </footer>
  );
}

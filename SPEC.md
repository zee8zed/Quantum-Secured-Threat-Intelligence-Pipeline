# Cyber Threat Intelligence Pipeline — Landing Page

## Context
Frontend landing page for a group project: "Quantum-secured threat intelligence NLP pipeline."
Backend team handles the actual pipeline (NER, quantum kernel classifier, CRYSTALS-Kyber encryption).
This task is landing page only — it loads, explains the project, and has a "Start" button.

## Where to build
Create a new `frontend/` folder at the repo root. Do not touch the existing Python ML folders
(`data/`, `notebooks/`, `src/`, `models/`, `outputs/`, `tests/`).

## Stack
- Next.js 14 with App Router and TypeScript
- Tailwind CSS
- shadcn/ui for base components (Button, Card, Badge)
- Framer Motion for scroll and hover animation
- Lucide React for icons
- Use pnpm if available, else npm
- Target: deployable to Vercel with zero config

## Design language
- Dark theme, background near-black (not pure black, ~#0a0a0f)
- Accent gradient: violet → cyan → teal
- Fonts: Inter for UI/body, JetBrains Mono for tech tags and code accents
- Vercel/Linear-inspired: generous whitespace, sharp typography, restrained motion
- Signature background: subtle animated particle network OR grid with drifting glow orbs
- Soft hover states, no harsh transitions
- No emoji in UI, no stock images, no lorem ipsum

## Page structure (single-page scroll)

1. **Hero**
   - Small pill row of tags: Quantum, NLP, ML, Cybersecurity
   - H1: "Quantum-secured threat intelligence, end to end."
   - Subtitle: one line explaining the pipeline
   - Primary button: "Start the pipeline" — onClick calls `startPipeline()` stub from `lib/actions.ts` that just console.logs. Leave a `// TODO: backend team wires this` comment.
   - Secondary button: "View on GitHub" — href from `REPO_URL` constant (placeholder "#")
   - Animated background

2. **The problem**
   - CVEs, dark web feeds, MITRE ATT&CK data are unstructured text
   - Existing pipelines are vulnerable to adversarial injection and interception

3. **How it works** — architecture flow
   - Horizontal flow: Raw Report → NER (BioBERT) → Quantum Kernel Classifier → CRYSTALS-Kyber Encryption → Encrypted JSON Brief
   - Each node has a short hover description
   - Animate flow on scroll into view

4. **What you get** — deliverable
   - Card explaining the end-to-end CLI: input raw report → NER → quantum classifier → post-quantum encrypted JSON brief

5. **Who it's for** — industry relevance
   - SOC teams, CERT agencies, threat intel platforms (Recorded Future / VirusTotal style)
   - SEBI and CERT-In mandates for Indian financial infrastructure

6. **Tech stack** grid
   - Badges: BioBERT, spaCy, Qiskit, PennyLane, CRYSTALS-Kyber, MITRE ATT&CK, scikit-learn, Python

7. **Footer**
   - Team credits (three placeholders)
   - Repo link (TODO constant)
   - Small monospace "built for X" tag

## Rules
- All not-yet-real URLs and names go in `frontend/lib/constants.ts` marked `TODO`
- Do not build backend routes, forms, or API handlers
- Add `frontend/README.md` with run instructions: `pnpm install && pnpm dev`
- Keep components in `frontend/components/`, sections in `frontend/components/sections/`

## Deliverable
`pnpm dev` on port 3000 shows the landing page. That's it.
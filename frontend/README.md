# Frontend — Landing Page

Landing page for the Quantum-Secured Threat Intelligence Pipeline. This is frontend only:
it loads, explains the project, and has a "Start" button. The actual pipeline (NER,
quantum kernel classifier, CRYSTALS-Kyber encryption) is owned by the backend team.

## Stack

- Next.js 14 (App Router) + TypeScript
- Tailwind CSS
- shadcn/ui-style components (Button, Card, Badge) in `components/ui/`
- Framer Motion for scroll/hover animation
- Lucide React for icons

## Run

```bash
pnpm install && pnpm dev
```

Open [http://localhost:3000](http://localhost:3000).

## Structure

- `app/` — root layout and the single page route
- `components/sections/` — one component per landing page section
- `components/ui/` — shadcn/ui-style base components
- `lib/constants.ts` — placeholder values (repo URL, team credits) marked `TODO`
- `lib/actions.ts` — `startPipeline()` stub the backend team will wire up

## Notes

- All not-yet-real URLs and names live in `lib/constants.ts`, marked `TODO`.
- No backend routes, forms, or API handlers are implemented here by design.

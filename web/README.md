# Synapse Web

Vite + React + TypeScript + Tailwind CSS v4 dashboard for Synapse.

## Dev

```bash
pnpm install
pnpm dev         # http://localhost:5173 (proxies /api and /healthz → :8080)
```

Run the Go API in parallel so the **Quick SCA scan** panel works:

```bash
# from repo root
make run
```

## Scripts

- `pnpm dev` – dev server with API proxy
- `pnpm build` – production build to `dist/`
- `pnpm preview` – preview the build
- `pnpm run typecheck` – `tsc --noEmit`

## Design system

Dark-mode-first, developer/terminal palette. Tokens live in `src/index.css`
(`@theme`) – Tailwind v4 turns `--color-card` into `bg-card`, etc. Fonts: Inter
(UI) + JetBrains Mono (data). Icons: lucide-react.

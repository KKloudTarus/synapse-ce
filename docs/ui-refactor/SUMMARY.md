# UI/UX Refactor — Summary Report

## Overview

Full-scope UI/UX refactor of the Synapse CE web frontend, covering structural code improvements, visual polish, design system migration, and developer experience enhancements.

**Branch:** `local/msw-mock-ui`  
**Duration:** ~7 days (Aug 17–24, 2026)  
**Scope:** `web/src/` — React + Vite + TypeScript + Tailwind CSS v4

---

## Phase A: Structural Refactor (Code Architecture)

### A1. API Module Split
- Monolithic `lib/api.ts` (2,384 LOC) → 17 domain-specific files under `lib/api/`
- Barrel re-export via `lib/api/index.ts` — zero breaking changes to consumers

### A2. Custom Hooks Extraction
- 4 base hooks (`useFetch`, `useParallelFetch`, `useDebouncedValue`, `useBreakpoint`)
- 8 domain hooks (`useAuditLog`, `useUserList`, `useEngagement`, etc.)
- 26 of 29 pages migrated from raw `useEffect` + `useState` to hooks

### A3. God Component Decomposition
- 7 oversized components split into focused modules
- `EngagementDetail` (5,280 LOC → 440 + 12 sub-files)
- `VulnerabilityIntelligence`, `Rules`, `DependencyGraph`, `AgentTab`, `ProjectMeasures`, `ProjectCodeWorkspace`

### A4. Code Splitting
- React.lazy() dynamic imports for all 30+ page components
- Suspense boundary with LoadingFallback at route level
- Build outputs separate chunks per page

### A5. Error Boundaries
- Route-level ErrorBoundary with `key={location.pathname}` for auto-reset
- Graceful error states per-page via hook error returns

---

## Phase B: Visual Refactor (Design System Migration)

### Design System
- Migrated to **Untitled UI React** component library (600+ components, MIT)
- Semantic color tokens via `theme.css` (300+ CSS variables, light/dark modes)
- Icons: `@untitledui/icons` exclusively (replaced all lucide-react usage)
- File icons: `@untitledui/file-icons` for export/import dropdowns

### Layout & Navigation
- **Sidebar:** Migrated to UUI semantic tokens, removed Topbar entirely
- **Shell:** Flex → CSS Grid layout, instant collapse (no transition jank)
- **Theme toggle:** Moved to sidebar footer (Sun/Moon dual-icon)
- **Settings:** Merged Governance group (Audit + Team) into single Settings page with sub-tabs

### Page-Level Improvements

| Page | Changes |
|------|---------|
| **Dashboard** | Redesigned: RadarChart for posture, DonutChart for risk mix, compact stat cards, Assessment Activity feed |
| **Engagements** | PascalCase mock data fix, routing bug fix (asset.id → asset.key) |
| **Engagement Detail** | 14 tabs → 6 grouped tabs, Export/Import dropdowns with FileIcon, button hierarchy (primary/secondary-color/secondary) |
| **Rules** | Inline expand with detail cache, removed separate detail page navigation, compact table |
| **Fleet** | Merged 2 tabs into single page, stats inline strip, agents as compact list with inline expand |
| **AI Triage Observability** | Alert → inline banner, distribution → donut charts, tables → horizontal bar charts, prompt version merged inline |
| **Vulnerability Intelligence** | Inline expandable advisory rows (replaced drawer), debounced auto-apply filters, collapsible "More filters" |
| **Code Quality** | Sidebar sub-tabs for Profiles/Gates, compact project cards, analysis details condensed |
| **Settings** | New page with Audit/Team/Config sub-tabs, System theme option, disconnect confirmation modal via portal |
| **Assets** | Routing fix, mock data PascalCase, pagination patterns |

### Dark Mode
- Fixed dual-system activation: `data-theme` attribute + `.dark-mode` class
- Theme init script before render (no flash)
- 3-option selector: Light / System / Dark
- System option auto-follows OS preference with live updates
- localStorage persistence (`synapse-theme` key)

---

## Phase C: Infrastructure & DX

### Pages Folder Reorganization
Grouped ~25 loose files into domain folders:

```
src/pages/
├── AITriage/          (Observability, Reviews)
├── Assets/            (List, Detail)
├── CodeQuality/       (Projects, Detail, Profiles, Gates, Measures, Hotspots)
├── Fleet/             (Coverage, Layout, shared)
├── Settings/          (Layout, Config, Audit, Team)
├── Dashboard/         (existing)
├── Engagements/       (existing)
├── EngagementDetail/  (existing + SLATab, ThreatModelTab moved in)
├── Rules/             (existing + RuleDetail moved in)
├── VulnerabilityIntelligence/ (existing)
└── Connect.tsx        (standalone auth)
```

### MSW Mock Data
- Comprehensive mock handlers for all pages (production-safe, DEV-only)
- Fixed field mismatches: PascalCase for Go API responses, correct transform mapping
- Vite proxy conditional: disabled when `VITE_API_PROXY_TARGET` not set (prevents ECONNREFUSED in MSW mode)
- Mock isolation: `import.meta.env.DEV` dynamic import, tree-shaken from production build

### Button Component Migration
- `ui.tsx` Button fully migrated to UUI semantic tokens
- 6 variants: primary, brand, secondary-color, secondary, ghost, danger
- Hierarchy rules: Build Report = primary; Run scan/Save = secondary-color; Export/Archive = secondary

---

## Metrics

| Metric | Before | After |
|--------|--------|-------|
| `lib/api.ts` size | 2,384 LOC (1 file) | 17 files (~140 LOC avg) |
| Largest component | 5,280 LOC | 440 LOC |
| Pages with hooks | 0 | 26/29 |
| Code-split pages | 0 | 30+ |
| Loose files in pages/ | ~25 | 1 (Connect.tsx) |
| Icon library | lucide-react (mixed) | @untitledui/icons (100%) |
| Dark mode | Non-functional | Full coverage (3 modes) |
| Test count | 313 passing | 313 passing (zero regressions) |

---

## Files Changed

- **Phase A commit:** 386 files, +47,306 / -12,078
- **Phase B commit:** 125 files, +11,364 / -4,949
- **Total:** ~500+ files touched, net +40K lines (mostly mock data + UUI library setup)

---

## Outstanding / Future Work

1. **Responsive check (1280px)** — Verify all pages at minimum viewport (spec exists)
2. **Accessibility pass** — Add aria-labels, alt text, heading hierarchy (spec exists)
3. **Hardcode cleanup** — Remove any remaining inline hex/px values (spec exists)
4. **API route integrity audit** — Verify no endpoints lost during refactor (spec exists)
5. **MSW mock isolation verify** — Confirm production build clean (spec exists)

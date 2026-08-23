# Dashboard Redesign Analysis

> Date: 2026-08-22
> Status: Proposed
> Scope: `web/src/pages/Dashboard/`

## Current State

The Dashboard currently has 3 sections stacked vertically:

1. **Hero Header** — large banner with title, subtitle, and 3 navigation buttons
2. **5 KPI Stat Cards** — Total assets, High-risk assets, Active engagements, Coverage gaps, Unassigned
3. **Telemetry (4 charts in 2×2 grid)**
   - Asset Security Posture (donut)
   - Findings Over Time (line chart)
   - Active Finding Risk Mix (donut)
   - Assets by Criticality (horizontal bar)
4. **Escalation (2 tables side-by-side)**
   - Priority Assets
   - Assessment Activity

---

## Problems Identified

### Redundant Information

| Element | Issue |
|---------|-------|
| "New Engagement" button in header | Already exists in sidebar. Removed. |
| "Asset inventory" + "Code security" buttons | These are primary sidebar navigation items. Redundant. |
| "High-risk assets" stat card | The "Asset Security Posture" donut already shows critical + high_risk breakdown. The stat card is just their sum. |
| "Unassigned" stat card | Engagements without an Asset is administrative housekeeping, not a security signal. Noise on an ops dashboard. |

### Chart Type Issues

| Chart | Problem |
|-------|---------|
| 2 Donut charts side-by-side | Visually similar (same severity colors, same shape), forcing users to read titles carefully to distinguish. Donuts are poor for comparing relative values across >4 segments. |
| "Assets by Criticality" bar chart | Shows user-assigned metadata (business criticality), not measured security state. Low actionability on an operational dashboard — belongs on the Assets detail page. |
| "Findings Over Time" line chart | ✅ Best chart here — shows trend, which is the most actionable signal. But buried in position 2 of 4. |

### Layout Issues

- Hero header burns ~200px vertical space for information available elsewhere
- Most actionable chart (trend) is not in the most prominent position
- Two donuts competing for attention dilutes both
- 2×2 chart grid forces all charts to equal visual weight regardless of importance

---

## Proposed Changes

### Remove

1. ~~"New Engagement" button~~ — already in sidebar (done)
2. **"Assets by Criticality" chart** — metadata, not security signal; move to `/assets`
3. ~~"Active Finding Risk Mix" donut~~ — **KEPT** (shows real measured risk, placed between Posture and Priority)
4. **"Unassigned" stat card** — housekeeping metric, not operational

### Change Chart Type

| Current | Proposed | Reason |
|---------|----------|--------|
| Asset Posture donut (large) | Stacked horizontal bar (single row, 100% width) | Compact, easier to compare proportions, works well with 5 segments |

### Elevate

- **Findings Over Time → full-width, first chart after stats** — trend is the most actionable signal on a security dashboard. It deserves hero positioning.

### Proposed Layout

```
┌──────────────────────────────────────────────────────┐
│  Compact header (title + subtitle, no nav buttons)    │
├─────────┬─────────┬─────────┬────────────────────────┤
│  Total  │ High-   │ Active  │  Coverage              │
│  Assets │  risk   │ Engage. │    Gaps                │
├─────────────────────────────────────┬────────────────┤
│  Findings Over Time (1fr)           │ Assessment     │
│  hero chart — trend signal          │ Activity (320) │
├──────────────────┬──────────────────┼────────────────┤
│ Asset Security   │ Active Finding   │ Priority       │
│ Posture (1fr)    │ Risk Mix (1fr)   │ Assets (320)   │
│ stacked bar      │ donut            │ feed list      │
└──────────────────┴──────────────────┴────────────────┘
```

Row 2 and Row 3 share the same column proportions:
- Left content area: `1fr` (or `1fr 1fr` split in row 3)
- Right panel: fixed `320px`

### Design Principles Applied

1. **Signal over noise** — only show metrics that prompt action
2. **Visual hierarchy = importance hierarchy** — trend chart (highest actionability) gets the most space
3. **No redundant navigation** — sidebar handles nav; dashboard shows data
4. **One chart type per insight** — avoid 2 donuts that look identical at a glance
5. **Compact density** — security operators scan, they don't read leisurely

---

## Changes Already Made

- [x] Removed "New Engagement" button from hero header (redundant with sidebar)
- [x] Hero section trimmed (compact title + subtitle only)
- [x] Removed "Assets by Criticality" chart
- [x] Removed "Unassigned" stat card → 4 cards remaining
- [x] Converted "Asset Security Posture" donut → stacked horizontal bar
- [x] "Findings Over Time" moved to hero position with Activity feed panel on right
- [x] Active Finding Risk Mix (donut) kept — placed between Posture and Priority
- [x] Layout: consistent column proportions (1fr content | 320px right panel)

## Remaining Work

- [ ] Stat card layout: flip to label-on-top, value-below (per UUI Sales Overview reference)
- [ ] Assessment Activity: convert to activity feed style (icon + name + status, no table grid)
- [ ] Figma reference: inspect frame `1719:453437` for exact spacing/typography

---

## References

- Dashboard source: `web/src/pages/Dashboard/`
- Chart components: `web/src/components/synapse/DashboardCharts.tsx`
- Data hook: `web/src/pages/Dashboard/hooks/useDashboardData.ts`
- Design tokens: `web/src/styles/theme.css`

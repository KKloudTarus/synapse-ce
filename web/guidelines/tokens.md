# Design Tokens

`web/src/styles/theme.css` defines the runtime design tokens (a Tailwind CSS v4
`@theme` block plus a `.dark-mode` override layer). It is the single source of truth for
their values. This guide does **not** restate those values — they drift the moment they
are copied. Instead it helps you **choose the right token** for a given interface, using
the token *names* you write as Tailwind utility classes.

When you need an exact value, read `theme.css`. When you need to know *which* token to
reach for, read this.

---

## How to think about tokens

Prefer **semantic** tokens (named for their role: `text-primary`, `bg-secondary`,
`border-error`) over raw scale utilities (`text-neutral-900`, `bg-red-500`). Semantic
tokens carry the correct value in both light and dark themes (see Dark mode below);
raw scale utilities do not adapt and should be avoided in product UI.

---

## Typography

**Font families** — `font-body` for all UI text, `font-display` for headings and hero
text, `font-mono` for code, data values, IDs, CVSS scores, and terminal output. Pair
`font-mono` with `tabular-nums` for aligned numeric columns.

**Font sizes** — the scale runs `text-xs` → `text-sm` → `text-md` → `text-lg` →
`text-xl`, then the display sizes `text-display-xs` … `text-display-2xl`. Rule of thumb:

- `text-xs` — captions, hints, small labels.
- `text-sm` — default body, button and input text.
- `text-md` — larger body and large-size inputs.
- `text-lg` / `text-xl` — card and section headers.
- `text-display-*` — page titles and marketing/hero headings (larger = more prominent).

**Font weights** — `font-regular` for body, `font-medium` for labels and nav items,
`font-semibold` for buttons, badges, tabs, and headings. Reserve `font-bold` for large
display numbers (e.g. stat-card values).

---

## Spacing

Spacing utilities (`p-*`, `gap-*`, `m-*`) share Tailwind's 4px base unit defined by
`--spacing` in `theme.css`. Choose by role rather than by pixel count:

- **Tight** (`gap-1`–`gap-2`) — icon-to-text, inline control-to-label.
- **Field-level** (`gap-1.5`–`gap-4`) — label-to-input, input-to-hint, between form
  fields.
- **Section-level** (`gap-6`–`gap-8`) — between content sections and cards.
- **Page-level** (`gap-8`–`gap-16`) — major page divisions and hero spacing.

Page authors control spacing *between* components; internal component padding is owned
by the components themselves (see `usage-rules.md`).

---

## Border radius

Radius tokens run `rounded-xs` → `rounded-sm` → `rounded-md` → `rounded-lg` →
`rounded-xl` → `rounded-2xl` → `rounded-3xl` → `rounded-full`. Conventions:

- Interactive controls (buttons, inputs, dropdowns) — `rounded-lg`.
- Containers, cards, and panels — `rounded-xl` (mobile modals) up to `rounded-2xl`
  (desktop modals).
- Pills, avatars, toggles — `rounded-full`.

---

## Shadows

Shadow tokens (`shadow-xs` → `shadow-sm` → `shadow-md` → `shadow-lg` → `shadow-xl` →
`shadow-2xl` → `shadow-3xl`, plus the skeuomorphic variants) encode **elevation**.
Pick by z-level, not by appearance: page content < cards (`shadow-xs`/`shadow-sm`) <
dropdowns and popovers (`shadow-md`/`shadow-lg`) < modals (`shadow-xl`). The
`shadow-xs-skeuomorphic` token gives filled buttons their subtle inner depth. Tertiary
buttons, text links, and toggles carry no shadow.

---

## Colours

### Semantic roles

Use the semantic families and let the token name describe intent:

- **Text** — `text-primary` (main copy, headings), `text-secondary` (supporting copy),
  `text-tertiary` / `text-quaternary` (progressively less important), `text-placeholder`
  (input placeholders only), `text-brand-secondary` (links, active items). Status text:
  `text-error-primary`, `text-warning-primary`, `text-success-primary`.
- **Background** — layer from `bg-primary` (page, cards) inward through `bg-secondary`
  (subtle sections, alternating rows), `bg-tertiary` (enclosed areas, code blocks), to
  `bg-quaternary` (rare deep nesting). `bg-brand-solid` is the primary action fill;
  `bg-error-solid` the destructive fill; `bg-overlay` the modal backdrop.
- **Border** — `border-primary` (default), `border-secondary` (subtle dividers),
  `border-brand` (focus/brand), `border-error` (invalid).
- **Foreground / icons** — the `fg-*` family (`fg-primary`, `fg-secondary`,
  `fg-tertiary`, `fg-quaternary`, `fg-brand-primary`, and the status `fg-*-primary`
  tokens) colours icons independently of text.

The **brand** family is Synapse's primary accent: use it for primary actions, focus
rings, links, active tabs, and selected items — not as a decorative fill.

### Utility colour ramps (badges, tags, charts)

`theme.css` exposes `utility-*` colour ramps (blue, red, green, yellow, orange, indigo,
purple, pink, sky, slate, emerald, amber, brand, neutral). These are consumed by the
Badge, Tag, and chart components rather than written directly. When you need a
categorical colour, choose it through those components' `color` prop so it stays
theme-aware.

---

## Focus & interaction

Interactive elements use a consistent focus treatment: a 2px brand outline with a 2px
offset (`focus-visible:outline-2 focus-visible:outline-offset-2 outline-brand`), and
`outline-error` for invalid inputs. The focus-ring colours are defined by
`--color-focus-ring` / `--color-focus-ring-error` in `theme.css`. Keep this treatment on
any custom interactive element you build.

---

## Layout limits

`theme.css` defines the responsive breakpoints (`xxs`, `xs`, plus Tailwind's defaults)
and the maximum content width (`max-width-container`). Constrain wide page content to the
container width rather than inventing new max-widths.

---

## Dark mode

The theme has two palettes in `theme.css`: a light palette on `:root` (the `@theme`
block) and a dark override under the `.dark-mode` class. The dark layer **remaps the
semantic role tokens** — the `text-*`, `bg-*`, `border-*`, `fg-*`, `ring-*`, and
`outline-*` families — and the `utility-*` colour ramps (roughly inverting each ramp,
e.g. `utility-red-50` resolves to a dark red). It does **not** remap the raw colour
scales (`--color-neutral-*`, `--color-red-*`, …), so raw scale utilities like
`bg-red-500` render the same in both themes.

The convention that follows:

1. Style surfaces with the **mapped semantic tokens** and pick categorical colours
   through the **utility-backed components** (Badge, Tag, charts). Those adapt.
2. Avoid raw colour-scale utilities and hardcoded colours; they will not.
3. **Verify every new surface in both light and dark** — a correct light appearance is
   not proof the dark mapping reads well. There is no guarantee that an arbitrary shade
   has a suitable dark counterpart, so check it.
</content>

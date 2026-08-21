# Design Tokens

> Source: `src/styles/theme.css` — Tailwind CSS v4 `@theme` block.
> Spacing unit: `--spacing` = 4px (Tailwind default). Ví dụ: `spacing-2` = 8px, `spacing-4` = 16px.

---

## Typography

### Font Families

| Token | Value | Khi nào dùng |
|-------|-------|--------------|
| `--font-body` | Inter, system fallbacks | Mọi UI text (labels, body, descriptions) |
| `--font-display` | Inter, system fallbacks | Headings, display text, hero sections |
| `--font-mono` | Roboto Mono, monospace fallbacks | Code snippets, data values, terminal output |

### Font Sizes

| Token | Size (px) | Line-height (px) | Letter-spacing | Khi nào dùng |
|-------|-----------|-------------------|----------------|--------------|
| `text-xs` | 12px | 18px | — | Hint text, labels nhỏ, captions |
| `text-sm` | 14px | 20px | — | Body text, button text, input text |
| `text-md` | 16px | 24px | — | Body lớn, input lg, tab text |
| `text-lg` | 18px | 28px | — | Section titles, card headers |
| `text-xl` | 20px | 30px | — | Page section headers |
| `text-display-xs` | 24px | 32px | — | Small display headings |
| `text-display-sm` | 30px | 38px | — | Page titles |
| `text-display-md` | 36px | 44px | -0.72px | Feature headers |
| `text-display-lg` | 48px | 60px | -0.96px | Hero headings |
| `text-display-xl` | 60px | 72px | -1.2px | Marketing hero |
| `text-display-2xl` | 72px | 90px | -1.44px | Landing page hero |

### Font Weights (Tailwind classes)

| Class | Khi nào dùng |
|-------|--------------|
| `font-regular` (400) | Body text, descriptions, hints |
| `font-medium` (500) | Labels, checkbox/toggle labels, nav items |
| `font-semibold` (600) | Buttons, badges, headings, tabs |
| `font-bold` (700) | Display headings (hiếm dùng) |

---

## Spacing Scale

> Base unit: 1 spacing = 4px. Dùng Tailwind classes: `p-2` = 8px, `gap-4` = 16px.

| Token/Class | Value | Khi nào dùng |
|-------------|-------|--------------|
| `spacing-0.5` | 2px | Micro gaps (ring insets, border offsets) |
| `spacing-1` | 4px | Icon-to-text gap nhỏ nhất |
| `spacing-1.5` | 6px | Label-to-input gap, compact spacing |
| `spacing-2` | 8px | Button padding (xs), inline gaps |
| `spacing-2.5` | 10px | Button padding (md vertical) |
| `spacing-3` | 12px | Input padding (sm/md), button padding (sm horiz) |
| `spacing-3.5` | 14px | Button padding (md horiz) |
| `spacing-4` | 16px | Card padding, section gaps, modal padding |
| `spacing-4.5` | 18px | Button padding (xl horiz) |
| `spacing-5` | 20px | Larger section gaps |
| `spacing-6` | 24px | Container padding, major section gaps |
| `spacing-8` | 32px | Page-level spacing, large gaps |
| `spacing-10` | 40px | Section separations |
| `spacing-12` | 48px | Major layout gaps |
| `spacing-16` | 64px | Page margins, hero spacing |

---

## Border Radius

| Token | Value | Khi nào dùng |
|-------|-------|--------------|
| `--radius-none` | 0px | Không bo tròn (table cells, dividers) |
| `--radius-xs` | 2px | Micro elements (shortcut badges) |
| `--radius-sm` | 4px | Tags nhỏ, inline badges |
| `--radius-DEFAULT` | 4px | Default fallback |
| `--radius-md` | 6px | Badges (color/modern type) |
| `--radius-lg` | 8px | **Buttons**, inputs, dropdowns, cards nhỏ |
| `--radius-xl` | 12px | Modals (mobile), cards, panels |
| `--radius-2xl` | 16px | Modals (desktop — `sm:rounded-2xl`) |
| `--radius-3xl` | 24px | Large containers (hiếm dùng) |
| `--radius-full` | 9999px | Avatars, pills, toggle switches, badges pill type |

---

## Shadows

| Token | Value | Khi nào dùng |
|-------|-------|--------------|
| `--shadow-xs` | `0px 1px 2px rgba(0,0,0,0.05)` | Inputs, small buttons (secondary) |
| `--shadow-sm` | `0px 1px 3px ...` | Cards nhỏ, dropdown items hover |
| `--shadow-md` | `0px 4px 6px ...` | Dropdown menus, popovers |
| `--shadow-lg` | `0px 12px 16px ...` | Tooltips, elevated cards |
| `--shadow-xl` | `0px 20px 24px ...` | Modals |
| `--shadow-2xl` | `0px 24px 48px ...` | Large floating panels |
| `--shadow-3xl` | `0px 32px 64px ...` | Hero mockups, marketing |
| `--shadow-skeuomorphic` | Inner border + bottom shadow | Button inner depth effect |
| `--shadow-xs-skeuomorphic` | Skeuomorphic + xs | **Primary/secondary buttons** |

---

## Colors

### Brand Scale

| Token | Light Mode | Khi nào dùng |
|-------|-----------|--------------|
| `brand-50` | `rgb(249 245 255)` | Brand background subtle |
| `brand-100` | `rgb(244 235 255)` | Brand hover states (bg) |
| `brand-200` | `rgb(233 215 254)` | On-brand secondary text |
| `brand-300` | `rgb(214 187 251)` | — |
| `brand-400` | `rgb(182 146 246)` | Dark mode brand border |
| `brand-500` | `rgb(158 119 237)` | Focus ring, brand secondary fg |
| `brand-600` | `rgb(127 86 217)` | **Primary CTA background**, brand fg |
| `brand-700` | `rgb(105 65 198)` | Brand solid hover, brand text |
| `brand-800` | `rgb(83 56 158)` | Brand section bg |
| `brand-900` | `rgb(66 48 125)` | Brand text primary |
| `brand-950` | `rgb(44 28 95)` | Dark mode brand bg |

### Semantic Colors — Text

| Token | Light | Dark | Khi nào dùng |
|-------|-------|------|--------------|
| `text-primary` | neutral-900 | neutral-50 | Main body text, headings |
| `text-secondary` | neutral-700 | neutral-300 | Supporting text, descriptions |
| `text-tertiary` | neutral-600 | neutral-400 | Placeholder-adjacent, less important |
| `text-quaternary` | neutral-500 | neutral-400 | Least important text, disabled-esque |
| `text-placeholder` | neutral-500 | neutral-500 | Input placeholders |
| `text-brand-secondary` | brand-700 | neutral-300 | Brand-colored text (links, active tabs) |
| `text-error-primary` | red-600 | red-400 | Error messages, destructive labels |
| `text-warning-primary` | yellow-600 | yellow-400 | Warning messages |
| `text-success-primary` | green-600 | green-400 | Success messages |

### Semantic Colors — Background

| Token | Light | Dark | Khi nào dùng |
|-------|-------|------|--------------|
| `bg-primary` | white | neutral-950 | Page background, cards |
| `bg-secondary` | neutral-50 | neutral-900 | Subtle sections, alternating rows |
| `bg-tertiary` | neutral-100 | neutral-800 | Input disabled bg, code blocks |
| `bg-quaternary` | neutral-200 | neutral-700 | Divider-weight backgrounds |
| `bg-brand-solid` | brand-600 | brand-600 | **Primary buttons**, solid brand bg |
| `bg-brand-solid_hover` | brand-700 | brand-500 | Primary button hover |
| `bg-brand-primary` | brand-50 | brand-500 | Brand-tinted section bg |
| `bg-error-solid` | red-600 | red-600 | Destructive button bg |
| `bg-error-primary` | red-50 | red-950 | Error alert bg |
| `bg-warning-primary` | yellow-50 | yellow-950 | Warning alert bg |
| `bg-success-primary` | green-50 | green-950 | Success alert bg |
| `bg-overlay` | neutral-950 | neutral-800 | Modal overlay (70% opacity + blur) |

### Semantic Colors — Border

| Token | Light | Dark | Khi nào dùng |
|-------|-------|------|--------------|
| `border-primary` | neutral-300 | neutral-700 | Default borders (inputs, cards) |
| `border-secondary` | neutral-200 | neutral-800 | Subtle separators, dividers |
| `border-tertiary` | neutral-100 | neutral-800 | Lightest border |
| `border-error` | red-500 | red-400 | Error state inputs |
| `border-error_subtle` | red-300 | red-500 | Error state secondary |
| `border-brand` | brand-500 | brand-400 | Focus state, brand border |

### Semantic Colors — Foreground (Icons)

| Token | Light | Dark | Khi nào dùng |
|-------|-------|------|--------------|
| `fg-primary` | neutral-900 | white | Primary icons |
| `fg-secondary` | neutral-700 | neutral-300 | Secondary icons |
| `fg-tertiary` | neutral-600 | neutral-400 | Tertiary icons |
| `fg-quaternary` | neutral-400 | neutral-600 | Muted icons (input trailing) |
| `fg-brand-primary` | brand-600 | brand-500 | Brand icons |
| `fg-error-primary` | red-600 | red-500 | Error icons |
| `fg-success-primary` | green-600 | green-500 | Success icons |
| `fg-warning-primary` | yellow-600 | yellow-500 | Warning icons |

### Utility Colors (for Badges, Tags, Charts)

Các utility colors tự động invert trong dark mode (50↔950, 100↔900...).

| Color | Shades available | Khi nào dùng |
|-------|------------------|--------------|
| `blue` | 50-700 | Info badges, links, charts |
| `red` | 50-700 | Error/destructive badges |
| `yellow` | 50-700 | Warning badges |
| `green` | 50-700 | Success badges |
| `orange` | 50-700 | Caution, progress |
| `indigo` | 50-700 | Categories, tags |
| `fuchsia` | 50-700 | Creative, highlight |
| `pink` | 50-700 | Social, marketing |
| `purple` | 50-700 | Premium, special |
| `sky` | 50-700 | Informational, light |
| `slate` | 50-700 | Neutral tags |
| `emerald` | 50-700 | Nature, sustainability |
| `amber` | 50-700 | Pending, caution |
| `brand` | 50-900 | Primary brand badges |
| `neutral` | 50-900 | Gray/default badges |

---

## Focus & Interaction

| Token | Value | Khi nào dùng |
|-------|-------|--------------|
| `--color-focus-ring` | brand-500 | Focus ring cho mọi interactive elements |
| `--color-focus-ring-error` | red-500 | Focus ring khi input invalid |
| Focus offset | `outline-offset-2` | Standard focus outline offset |
| Focus width | `outline-2` | Standard focus ring width |

---

## Breakpoints

| Token | Value | Khi nào dùng |
|-------|-------|--------------|
| `--breakpoint-xxs` | 320px | Smallest mobile |
| `--breakpoint-xs` | 600px | Mobile landscape, toast breakpoint |
| `--max-width-container` | 1280px | Max content width |

---

## Animations

| Token | Value | Khi nào dùng |
|-------|-------|--------------|
| `--animate-marquee` | 60s linear infinite translate | Scrolling ticker/marquee |
| `--animate-caret-blink` | 1s infinite opacity blink | Cursor/caret indicators |
| Modal enter | `300ms ease-out, fade-in + zoom-in-95` | Modal/dialog opening |
| Modal exit | `200ms ease-in, fade-out + zoom-out-95` | Modal/dialog closing |
| Tooltip enter | `ease-out animate-in fade-in zoom-in-95` | Tooltip appear |
| Tooltip exit | `ease-in animate-out fade-out zoom-out-95` | Tooltip disappear |
| Transitions | `duration-100 ease-linear` | Buttons, inputs, icons |
| Toggle | `duration-150 ease-linear` | Toggle switch state |

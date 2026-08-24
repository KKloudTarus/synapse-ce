# Usage Rules

Conventions for composing Synapse pages with the shared design system. Where `tokens.md`
covers *which* token to use and `components.md` covers *which* component to use, this
guide covers *how to put them together* into a consistent page.

---

## What a page author controls

Shared components own their **internal** spacing — the padding inside a button, input,
tab, badge, or modal. Do not override it. Your job as a page author is the layout
*around* and *between* components:

- **Space between sections** — use section-level gaps (`gap-6`–`gap-8`); reserve larger
  page-level gaps for major divisions. See the spacing scale in `tokens.md`.
- **Grid and flex gaps** — set the `gap-*` between cards, stats, and columns.
- **Container padding** — the responsive page container uses a pattern like
  `px-4 sm:px-6 lg:px-8`; keep page content within it.
- **Content width** — constrain wide content to `max-width-container` rather than
  inventing new max-widths.
- **Responsive layout** — collapse multi-column grids to single column on small
  screens; make wide tables and code blocks scroll inside their own container.
- **Action placement** — where the primary and secondary actions sit in a header,
  toolbar, or card footer.

---

## Actions and hierarchy

**Use one primary action per action group.** Style the remaining actions in that group
as secondary or tertiary. An "action group" is any cluster of controls that belong
together — a page header, a card footer, a modal footer, a toolbar. A page may contain
several action groups, each with its own single primary action.

Express emphasis through the `Button` `color` prop, most to least prominent:

`primary` → `secondary` → `tertiary` → `link-color` → `link-gray`

Use the `*-destructive` colours for delete/remove, and always confirm irreversible
actions in a `Modal`.

---

## Colours

- **Use semantic colour tokens** for surfaces, text, borders, and icons
  (`text-primary`, `bg-secondary`, `border-primary`, `fg-tertiary`, …). Pick categorical
  colours (status, tags, charts) through the components that consume the `utility-*`
  ramps — the `color` prop on `Badge`, `Tag`, and charts.
- **Do not write raw colour values** — no hex/rgb, and avoid raw scale utilities like
  `bg-red-500`, which are not theme-aware.
- **Reserve brand for meaning** — primary actions, focus, links, active/selected state.
- **Verify each surface in light and dark.** See the token roles and dark-mode mappings
  in `tokens.md`.

---

## Dark mode

Light and dark are driven by token mappings in `theme.css`, not by per-component work:
the `.dark-mode` layer remaps the semantic role tokens (`text-*`, `bg-*`, `border-*`,
`fg-*`, `ring-*`, `outline-*`) and the `utility-*` colour ramps. If you style with those
mapped tokens, surfaces adapt automatically. Because raw colour scales are **not**
remapped, and no arbitrary shade is guaranteed a good dark counterpart, review every new
surface in both themes before shipping.

---

## Accessibility

The base components are built on React Aria and ship real accessibility behaviour. Your
job is to compose them so that behaviour survives — distinguish what the component
guarantees from what correct usage requires:

| The component guarantees | You are responsible for |
|---|---|
| Keyboard interaction (activation, arrow-key navigation, roving tabindex) | Not replacing components with bare `<div>`s that drop it; giving icon-only controls an accessible label |
| Associating `label`, `hint`, and error text with a field | Actually passing `label` and hint/error via the component API instead of relying on `placeholder` |
| Focus containment and `Escape`-to-close in `Modal` / `SlideoutMenu` | Keeping that behaviour enabled — don't disable focus management or intercept `Escape` |
| Exposing checked/disabled state to assistive tech | Using the `isDisabled` / selection props rather than visually faking those states |
| Opening tooltips on focus as well as hover | Attaching tooltips to focusable triggers |

After composing a flow, test it with the keyboard alone — tab order, activation, and
dismissal should all work.

---

## Page layout and the app shell

Synapse has **one canonical app shell**; individual pages do not build their own
navigation. The shell is defined in `web/src/App.tsx` (the `Shell` component) and
`web/src/components/layout/Sidebar.tsx`. It composes the persistent `Sidebar` (plus a
`MobileSidebar`), an error boundary, and a `Suspense` fallback, and renders the active
route into a `<main>` region via React Router's `<Outlet />`.

Because the shell owns navigation, **a page component begins at its own header**, not at
a sidebar or top nav. A typical list/table page renders, in order:

```tsx
export function ExamplePage() {
  return (
    <div className="space-y-6">
      {/* 1. Page header: title + primary action for this group */}
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-display-sm font-semibold text-primary">Engagements</h1>
        <Button color="primary" iconLeading={Plus}>New engagement</Button>
      </div>

      {/* 2. Filters */}
      <FilterBar.Root>{/* … */}</FilterBar.Root>

      {/* 3. Primary content */}
      <Table>{/* … */}</Table>

      {/* 4. Pagination */}
      <PaginationLine page={page} total={total} onPageChange={setPage} />
    </div>
  );
}
```

The route is what places this page inside the shell (see the `<Route>` table in
`App.tsx`); the page itself only owns the content region.

---

## Common composition patterns

### Form field

```tsx
<Input label="Email" hint="We'll never share it" placeholder="you@example.com" icon={Mail} isRequired />
```

### Confirmation modal

```tsx
<DialogTrigger>
  <Button color="primary-destructive">Delete</Button>
  <ModalOverlay>
    <Modal>
      <Dialog>{/* header + body + footer: one primary action, rest secondary */}</Dialog>
    </Modal>
  </ModalOverlay>
</DialogTrigger>
```

### Empty state

```tsx
<EmptyState.Root>
  <EmptyState.FeaturedIcon icon={SearchLg} />
  <EmptyState.Header title="No results" description="Try adjusting your filters" />
  <EmptyState.Actions>
    <Button color="secondary">Clear filters</Button>
  </EmptyState.Actions>
</EmptyState.Root>
```

### Stat / KPI card

Keep stat cards consistent: the label sits above the value, semibold but lighter than
the value; the value is the largest, boldest element and uses `tabular-nums`; an optional
hint sits below.

```tsx
<div className="rounded-xl border border-secondary bg-primary p-4 shadow-xs">
  <div className="flex items-center justify-between">
    <span className="text-sm font-semibold text-secondary">Open findings</span>
    <Icon className="text-fg-quaternary" aria-hidden />
  </div>
  <div className="text-display-sm font-bold tabular-nums text-primary">142</div>
  <p className="text-xs text-tertiary">+12 this week</p>
</div>
```

### Loading, empty, and error states

Every data view must handle all three. Use `LoadingIndicator` (or a skeleton) while
loading, `EmptyState` for no-results, and a clear error surface on failure — never leave
a blank region.

---

## Choosing a component

| You need | Use |
|---|---|
| Main / secondary / destructive action | `Button` with the matching `color` |
| Text link | `Button color="link-color"` (brand) or `"link-gray"` (neutral) |
| Single-line text, email, password, search | `Input` |
| Multi-line text | `TextArea` |
| Number with steppers | `InputNumber` |
| Date / date range | `DatePicker` / `DateRangePicker` |
| File upload | `FileUpload` (drop zone) or `FileUploadTrigger` (button) |
| Tag entry | `InputTags` |
| One of N (dropdown) | `Select` |
| One of N (inline) | `RadioGroup` |
| Many of N (dropdown) | `MultiSelect` |
| Many of N (inline) | `Checkbox` list |
| Searchable selection | `ComboBox` |
| On/off setting | `Toggle` |
| Single agreement/confirmation | `Checkbox` |
| Numeric range | `Slider` |
| Status / category label | `Badge` |
| User identity | `Avatar` |
| Contextual help | `Tooltip` |
| Confirm a dangerous action | `Modal` + destructive button |
| Detail side panel | `SlideoutMenu` |
| In-page section switching | `Tabs` |
| Tabular data | `Table` (or `VirtualTable` for large sets) |
| Loading state | `LoadingIndicator` |
| Determinate progress | `ProgressBar` |
| Empty / no-results state | `EmptyState` |
| Filter controls | `FilterBar` |
| Command palette (⌘K) | `CommandMenu` |
| Contextual menu | `Dropdown` (pick the variant file) |
| List pagination | `PaginationLine` / `PaginationDot` |
</content>

# Usage Rules

> Quy tắc thực tế để compose pages đúng design system. Inferred từ component source code patterns.

---

## Spacing Rules

### Component Internal Padding

| Component | Size SM | Size MD | Size LG |
|-----------|---------|---------|---------|
| Button | `py-1.5 px-2.5` (6px/10px) | `py-2.5 px-3.5` (10px/14px) | `py-2.5 px-4` (10px/16px) |
| Input | `py-2 px-3` (8px/12px) | `py-2 px-3` (8px/12px) | `py-2.5 px-3.5` (10px/14px) |
| Tabs (button) | `py-2 px-2.5` | `py-2.5 px-2.5` | — |
| Modal padding | `p-4` (16px mobile) | `p-6` (24px desktop) | — |

### Gap Rules (khoảng cách giữa elements)

| Context | Gap | Ví dụ |
|---------|-----|-------|
| Icon ↔ text (nhỏ) | `gap-1` (4px) | Button xs/sm icon + text |
| Icon ↔ text (lớn) | `gap-1.5` (6px) | Button lg/xl icon + text |
| Label ↔ input | `gap-1.5` (6px) | Form field label → input |
| Input ↔ hint | `gap-1.5` (6px) | Input → helper text dưới |
| Toggle/Checkbox ↔ label | `gap-2` (8px) sm, `gap-3` (12px) md | Inline controls |
| Form fields | `gap-4` to `gap-6` (16-24px) | Giữa các form groups |
| Section ↔ section | `gap-6` to `gap-8` (24-32px) | Giữa các content sections |
| Page sections | `gap-8` to `gap-16` (32-64px) | Major page divisions |

### Padding Patterns

| Element | Padding |
|---------|---------|
| Card/Panel | `p-4` (16px) hoặc `p-6` (24px) |
| Modal body | `p-6` (24px) |
| Sidebar | `p-4` hoặc `px-3 py-4` |
| Table cell | `px-6 py-4` (typical) |
| Page container | `px-4 sm:px-6 lg:px-8` |
| Dropdown items | `px-2.5 py-2` |
| Tooltip | `px-3 py-2` (title only), `px-3 py-3` (with description) |

---

## Radius Rules

| Component | Radius | Token |
|-----------|--------|-------|
| **Buttons** (tất cả sizes) | `rounded-lg` (8px) | `radius-lg` |
| **Inputs** | `rounded-lg` (8px) | `radius-lg` |
| **Cards** | `rounded-xl` (12px) | `radius-xl` |
| **Modals** (mobile) | `rounded-xl` (12px) | `radius-xl` |
| **Modals** (desktop) | `rounded-2xl` (16px) | `radius-2xl` |
| **Badges** (pill type) | `rounded-full` (9999px) | `radius-full` |
| **Badges** (color/modern) | `rounded-md` (6px) | `radius-md` |
| **Checkbox** (sm) | `rounded` (4px) | `radius-sm` |
| **Checkbox** (md) | `rounded-md` (6px) | `radius-md` |
| **Toggle** | `rounded-full` | `radius-full` |
| **Avatar** | `rounded-full` | `radius-full` |
| **Tooltip** | `rounded-lg` (8px) | `radius-lg` |
| **Tabs** (border type) | `rounded-[10px]` container, items inside | Custom |
| **Tags** | `rounded-md` to `rounded-full` | Varies |
| **Dropdown menu** | `rounded-lg` to `rounded-xl` | `radius-lg/xl` |
| **Shortcut badge** | `rounded` (4px) | `radius-sm` |

**Rule:** Hầu hết interactive elements = `rounded-lg`. Containers/panels = `rounded-xl/2xl`. Pill shapes = `rounded-full`.

---

## Shadow Rules

| Context | Shadow | Khi nào |
|---------|--------|---------|
| **Buttons** (primary/secondary) | `shadow-xs-skeuomorphic` | Mọi filled buttons |
| **Inputs** | `shadow-xs` | Default state |
| **Cards** nhỏ | `shadow-sm` | Elevated cards |
| **Dropdowns/Popovers** | `shadow-md` to `shadow-lg` | Floating menus |
| **Tooltips** | `shadow-lg` | Tooltip container |
| **Modals** | `shadow-xl` | Modal panel |
| **Tabs** (minimal type) | `shadow-xs` + `ring-1` | Selected tab item |
| **Marketing/Mockups** | `shadow-2xl` to `shadow-3xl` | Hero sections |
| **Badge** (modern) | `shadow-xs` | Modern badge variant |
| **No shadow** | — | Tertiary buttons, text links, toggles |

**Rule:** Shadow depth tăng theo z-level: page content < cards < dropdowns < tooltips < modals.

---

## Color Rules

### Semantic Meaning

| Color | Meaning | Dùng cho |
|-------|---------|----------|
| **Brand** (purple) | Primary action, active state | CTAs, links, focus rings, selected items, active tabs |
| **Error/Red** | Destructive, invalid, failure | Delete buttons, form errors, error alerts, destructive badges |
| **Warning/Yellow** | Caution, attention needed | Warning alerts, pending states |
| **Success/Green** | Positive, completed | Success alerts, completed status, valid states |
| **Neutral/Gray** | Default, secondary | Secondary actions, borders, disabled, placeholder |

### Button Color Hierarchy

```
Quan trọng nhất → ít quan trọng nhất:

primary (brand solid)  →  secondary (white + border)  →  tertiary (ghost)  →  link-color  →  link-gray
```

**Rule:** Mỗi page section chỉ nên có **1 primary button**. Các actions khác dùng secondary/tertiary.

### Text Color Hierarchy

```
text-primary   → Main content, headings
text-secondary → Descriptions, supporting text
text-tertiary  → Less important info, timestamps
text-quaternary → Least important, icons muted
text-placeholder → Input placeholder only
```

### Background Layering

```
bg-primary (white/950) → Main page, cards
  └── bg-secondary (50/900) → Subtle sections, table alternating
       └── bg-tertiary (100/800) → Enclosed areas, code blocks
            └── bg-quaternary (200/700) → Deep nesting (rare)
```

---

## Typography Rules

### Heading Levels

| Level | Font | Khi nào dùng |
|-------|------|--------------|
| h1 (Page title) | `text-display-sm font-semibold` (30px) | Page top-level heading |
| h2 (Section) | `text-xl font-semibold` (20px) | Major sections |
| h3 (Subsection) | `text-lg font-semibold` (18px) | Cards headers, sub-sections |
| h4 (Small header) | `text-md font-semibold` (16px) | Small card titles |

### Body Text

| Context | Font |
|---------|------|
| Body default | `text-sm text-secondary` (14px) |
| Body large | `text-md text-secondary` (16px) |
| Labels (form) | `text-sm font-medium text-secondary` |
| Hints/Descriptions | `text-sm text-tertiary` |
| Captions/Footnotes | `text-xs text-tertiary` |
| Button text | `text-sm font-semibold` (xs-md) / `text-md font-semibold` (lg-xl) |
| Badge text | `text-xs font-medium` (sm) / `text-sm font-medium` (md-lg) |
| Tooltip | `text-xs font-semibold text-white` |
| Tab text | `text-sm font-semibold` (sm) / `text-md font-semibold` (md) |

---

## Component Selection Guide

| Cần gì? | Dùng component nào |
|---------|-------------------|
| Main action (CTA) | `Button color="primary"` |
| Secondary action | `Button color="secondary"` |
| Destructive action | `Button color="primary-destructive"` |
| Text link (brand) | `Button color="link-color"` |
| Text link (neutral) | `Button color="link-gray"` |
| Input text | `Input` |
| Input long text | `Textarea` |
| Input number | `InputNumber` |
| Input date | `DatePicker` |
| Input date range | `DateRangePicker` |
| Input file | `FileUpload` (drag-drop) or `FileUploadTrigger` (button) |
| Input tags | `InputTags` |
| Chọn 1 trong N (dropdown) | `Select` |
| Chọn 1 trong N (inline) | `RadioButtons` |
| Chọn nhiều (dropdown) | `MultiSelect` |
| Chọn nhiều (inline) | `Checkbox` (multiple) |
| Chọn với search | `Combobox` |
| On/Off toggle | `Toggle` |
| Agree/confirm | `Checkbox` (single) |
| Range/slider | `Slider` |
| Hiện status | `Badge` |
| Hiện user | `Avatar` |
| Tooltip info | `Tooltip` |
| Confirm dangerous action | `Modal` + destructive buttons |
| Side panel detail | `SlideoutMenu` |
| Tab navigation | `Tabs` |
| Table data | `Table` |
| Loading state | `LoadingIndicator` |
| Progress | `ProgressIndicators` |
| Empty state | `EmptyState` |
| Filter controls | `FilterBar` |
| Command palette (⌘K) | `CommandMenu` |
| Dropdown menu | `Dropdown` (pick variant) |
| Sidebar nav | `Sidebar*` variants |
| Top nav | `HeaderNavigation` |
| Page pagination | `Pagination` |
| Carousel/slider | `Carousel` |

---

## Dark Mode Rules

- Semantic tokens **tự động swap** trong `.dark-mode` class
- KHÔNG hardcode color values — luôn dùng semantic tokens (`text-primary`, `bg-secondary`, etc.)
- Utility colors invert (50↔950, 100↔900...) → Badges, tags tự adapt
- `--color-alpha-white` → black trong dark mode (dùng cho inverted surfaces)
- Test cả light + dark mode khi chọn colors

---

## Accessibility Rules

- Mọi interactive elements có `focus-visible:outline-2 outline-offset-2`
- Focus ring color: `outline-brand` (brand-500) default, `outline-error` (red-500) for error inputs
- Buttons: dùng React Aria `Button` → handles keyboard, aria-disabled
- Inputs: connect `label` + `hint` via aria-labelledby/describedby
- Modals: trap focus, handle Escape key (via React Aria)
- Disabled: `opacity-50 cursor-not-allowed`, NOT removed from DOM
- Checkboxes/Toggles: proper checked/unchecked states via React Aria
- Tooltips: triggered by focus too, not just hover

---

## Composition Patterns

### Form Field
```
<Input label="Email" hint="We'll never share your email" placeholder="you@example.com" icon={Mail} isRequired />
```

### Modal Confirmation
```
<DialogTrigger>
  <Button color="primary-destructive">Delete</Button>
  <ModalOverlay>
    <Modal>
      <Dialog>
        {/* Header + content + footer with cancel + confirm buttons */}
      </Dialog>
    </Modal>
  </ModalOverlay>
</DialogTrigger>
```

### Page Layout
```
<SidebarSimple>         ← Navigation
  <HeaderNavigation>    ← Top bar
    <main>
      <h1 class="text-display-sm font-semibold text-primary">Title</h1>
      <FilterBar />     ← Filters
      <Table />         ← Data
      <Pagination />    ← Pagination
    </main>
  </HeaderNavigation>
</SidebarSimple>
```

### Empty State
```
<EmptyState.Root>
  <EmptyState.FeaturedIcon icon={SearchLg} />
  <EmptyState.Header title="No results" description="Try adjusting your filters" />
  <EmptyState.Actions>
    <Button color="secondary">Clear filters</Button>
    <Button color="primary">New item</Button>
  </EmptyState.Actions>
</EmptyState.Root>
```

# Component Catalogue

Where the shared building blocks live:

- **`@/components/base/`** — shared UI **primitives** (buttons, inputs, selects,
  checkboxes, badges, avatars, tooltips, and so on). These are React Aria Components
  under the hood, so they ship keyboard and ARIA behaviour by default.
- **`@/components/application/`** — reusable **application components** assembled from the
  primitives (tables, modals, tabs, pagination, date pickers, command menus, navigation
  shells, and so on).

Two related directories exist but are out of scope for this catalogue:
`@/components/synapse/` holds Synapse-specific domain components (e.g. severity badges,
page state placeholders, the virtualized table), and `@/components/foundations/` holds
icon/logo/illustration primitives. The app shell itself lives in `@/components/layout/`
(see `usage-rules.md`).

All icons come from `@untitledui/icons`. The `@` import alias resolves to `web/src`.

### How to read the labels

Each entry is tagged so you can tell how it fits Synapse:

- **Preferred** — the component to standardize on for this need.
- **Variant** — an alternative the library supports; use it when the specific case calls
  for it.
- **Building block** — a lower-level or specialized piece you compose manually, or a
  library shell Synapse does not use as-is.

This catalogue focuses on the public contract: the import, the key props, the supported
variants, when to use it, and its accessibility behaviour. It deliberately omits internal
styling (radius/shadow/padding/ring classes) — those belong to the component and are not
part of its contract.

---

## Buttons

### Button — *Preferred*

```ts
import { Button } from "@/components/base/buttons/button";
```

Key props: `size` (`"xs" | "sm" | "md" | "lg" | "xl"`, default `"sm"`), `color`
(`"primary" | "secondary" | "tertiary" | "link-color" | "link-gray" |
"primary-destructive" | "secondary-destructive" | "tertiary-destructive" |
"link-destructive"`, default `"primary"`), `iconLeading`, `iconTrailing`, `isDisabled`,
`isLoading`, `showTextWhileLoading`, `href` (renders an anchor).

Use `color` to express hierarchy: `primary` for the main action, `secondary` for
supporting actions, `tertiary` for low-emphasis (ghost) actions, `link-*` for text
links, and the `*-destructive` variants for delete/remove actions.

Accessibility: built on React Aria `Button` — full keyboard activation, and disabled
state exposed via `aria-disabled` (the element stays in the DOM and focusable behaviour
is handled for you). Pass an accessible label when the button is icon-only.

```tsx
<Button color="primary" iconLeading={Plus} onClick={onCreate}>New engagement</Button>
```

### ButtonUtility — *Building block*

```ts
import { ButtonUtility } from "@/components/base/buttons/button-utility";
```

Small icon-only button (close, settings, menu toggle). Requires an accessible label.

### CloseButton — *Building block*

```ts
import { CloseButton } from "@/components/base/buttons/close-button";
```

The dismiss (×) control for modals, slideouts, and alerts. Takes a `label`, `size`, and
`theme`.

### ButtonGroup — *Variant*

```ts
import { ButtonGroup, ButtonGroupItem } from "@/components/base/button-group/button-group";
```

Segmented group of adjoining actions. Compose `ButtonGroupItem` children inside
`ButtonGroup`.

---

## Inputs & forms

### Input — *Preferred*

```ts
import { Input } from "@/components/base/input/input";
```

Key props: `size` (`"sm" | "md" | "lg"`, default `"md"`), `label`, `hint`,
`placeholder`, `icon` (leading), `tooltip`, `shortcut`, `isInvalid`, `isDisabled`,
`isRequired`, `type`. The `password` type gets a reveal toggle automatically.

Accessibility: `label`, `hint`, and error state are wired to the field via React Aria, so
screen readers announce the label and description. Always pass `label` (or an accessible
label) rather than a bare `placeholder`.

```tsx
<Input label="Email" hint="We'll never share it" placeholder="you@example.com" icon={Mail} isRequired />
```

`@/components/base/input/input.tsx` also exports `TextField` and `InputBase` as building
blocks for custom field layouts.

### Specialized inputs — *Variant*

Each lives in its own module under `@/components/base/input/`:

```ts
import { InputNumber } from "@/components/base/input/input-number";
import { InputDate } from "@/components/base/input/input-date";
import { InputFile } from "@/components/base/input/input-file";
import { InputTags } from "@/components/base/input/input-tags";
import { PinInput } from "@/components/base/input/pin-input";
import { InputGroup } from "@/components/base/input/input-group";
```

`InputNumber` (stepper), `InputDate`, `InputFile`, `InputTags`, `PinInput` (OTP), and
`InputGroup` (input paired with prefix/addon controls).

### Textarea — *Preferred*

```ts
import { TextArea } from "@/components/base/textarea/textarea";
```

Key props: `size` (`"sm" | "md"`), `label`, `hint`, `isResizable`. Same labelling
contract as `Input`.

### Select — *Preferred*

```ts
import { Select } from "@/components/base/select/select";
```

Key props: `size` (`"sm" | "md" | "lg"`), `label`, `placeholder`, `isInvalid`. Compose
`SelectItem` children (`@/components/base/select/select-item`).

Accessibility: React Aria listbox behaviour — arrow-key navigation, type-ahead, and
`aria-expanded` are handled. Provide a `label`.

Related selection components — *Variant*:

```ts
import { MultiSelect } from "@/components/base/select/multi-select";
import { ComboBox } from "@/components/base/select/combobox";
import { TagSelect } from "@/components/base/select/tag-select";
import { NativeSelect } from "@/components/base/select/select-native";
```

Choose `Select` for one-of-N, `MultiSelect` for many, `ComboBox` for searchable
selection, `TagSelect` for token/category selection, and `NativeSelect` where a native
control is preferable (e.g. simple mobile forms).

### Checkbox / RadioGroup / Toggle — *Preferred*

```ts
import { Checkbox } from "@/components/base/checkbox/checkbox";
import { RadioGroup, RadioButton } from "@/components/base/radio-buttons/radio-buttons";
import { Toggle } from "@/components/base/toggle/toggle";
```

`Checkbox` (single confirmation or multi-select list; `size`, `label`, `hint`),
`RadioGroup` wrapping `RadioButton` children (exclusive choice), and `Toggle`
(`size`, `slim`, `label`, `hint`) for on/off settings. All expose their checked state
through React Aria.

### Slider — *Variant*

```ts
import { Slider } from "@/components/base/slider/slider";
```

Range/numeric slider (`minValue`, `maxValue`, `formatOptions`, `labelPosition`).

### Form — *Building block*

```ts
import { Form } from "@/components/base/form/form";
import { HookForm, FormField } from "@/components/base/form/hook-form";
```

`Form` is the React Aria form wrapper. `HookForm` + `FormField` integrate the fields with
React Hook Form for validation-driven forms.

---

## Data display

### Badge — *Preferred*

```ts
import { Badge } from "@/components/base/badges/badges";
```

Key props: `size` (`"sm" | "md" | "lg"`), `color` (utility colour such as `"gray"`,
`"brand"`, `"error"`, `"warning"`, `"success"`, `"blue"`, `"indigo"`, `"purple"`, …),
`type` (`"pill-color" | "color" | "modern"`), plus optional `dot`, `avatar`, `flag`, and
`onDismiss`. Choosing colour via the `color` prop keeps the badge theme-aware.

Use `pill-color` + a status colour for status indicators, `color` for categories/tags,
and `modern` + gray for counts/labels. `badges.tsx` also exports pre-composed variants
(`BadgeWithDot`, `BadgeWithIcon`, `BadgeWithButton`, …) as building blocks.

### Avatar — *Preferred*

```ts
import { Avatar } from "@/components/base/avatar/avatar";
```

User avatar (image or initials) with optional online/verified indicators. Provide `alt`
text.

### Tags — *Variant*

```ts
import { Tag, TagGroup, TagList } from "@/components/base/tags/tags";
```

Dismissible tag chips for filters and selected items. Compose `Tag` inside
`TagGroup` / `TagList`.

### Table — *Preferred*

```ts
import { Table, TableCard } from "@/components/application/table/table";
```

Data table with sortable columns and selectable rows. For large result sets prefer the
virtualized `VirtualTable` in `@/components/synapse/VirtualTable`.

### Charts — *Building block*

```ts
import { ChartTooltipContent, ChartLegendContent } from "@/components/application/charts/charts-base";
```

`charts-base` is a toolkit of chart pieces (tooltip, legend, active-dot) layered over the
charting library rather than a single drop-in chart. Synapse's dashboards compose these
via `@/components/synapse/DashboardCharts` and page-local chart cards.

### EmptyState — *Preferred*

```ts
import { EmptyState } from "@/components/application/empty-state/empty-state";
```

Compound component: `EmptyState.Root` (size), `EmptyState.FeaturedIcon`,
`EmptyState.Illustration`, `EmptyState.Header` (title + description), and
`EmptyState.Actions`. Use for empty tables, no-results, and first-run states.

```tsx
<EmptyState.Root>
  <EmptyState.FeaturedIcon icon={SearchLg} />
  <EmptyState.Header title="No results" description="Try adjusting your filters" />
  <EmptyState.Actions>
    <Button color="secondary">Clear filters</Button>
  </EmptyState.Actions>
</EmptyState.Root>
```

---

## Feedback & overlays

### Tooltip — *Preferred*

```ts
import { Tooltip, TooltipTrigger } from "@/components/base/tooltip/tooltip";
```

Key props: `title`, `description`, `placement` (default `"top"`), `arrow`, `delay`.
Accessibility: React Aria opens the tooltip on focus as well as hover, so keyboard users
reach it too.

### Modal / Dialog — *Preferred*

```ts
import { DialogTrigger, ModalOverlay, Modal, Dialog } from "@/components/application/modals/modal";
```

`DialogTrigger` wraps the trigger and modal; `ModalOverlay` is the backdrop; `Modal` is
the container; `Dialog` holds scrollable content. Accessibility: React Aria traps focus
inside the modal and closes it on `Escape` — keep that behaviour intact (see
`usage-rules.md`). Use for confirmations, forms, and destructive-action confirms.

### SlideoutMenu — *Preferred*

```ts
import { SlideoutMenu } from "@/components/application/slideout-menus/slideout-menu";
```

Side drawer for detail views and settings panels. Like Modal, it manages focus
containment and `Escape`.

### LoadingIndicator — *Preferred*

```ts
import { LoadingIndicator } from "@/components/application/loading-indicator/loading-indicator";
```

Spinner/skeleton for loading states (`type`, `size`, `label`).

### ProgressBar — *Variant*

```ts
import { ProgressBar } from "@/components/base/progress-indicators/progress-indicators";
```

Determinate progress bar (`value`, `min`, `max`, `valueFormatter`, `labelPosition`).

---

## Navigation

### Tabs — *Preferred*

```ts
import { Tabs, TabList, Tab, TabPanel } from "@/components/application/tabs/tabs";
```

Key props on `TabList`: `size` (`"sm" | "md"`), `type` (horizontal:
`"button-brand" | "button-gray" | "button-border" | "button-minimal" | "underline"`;
vertical adds `"line"`), `orientation`, `fullWidth`. Compose `Tab` (label/icon/badge)
inside `TabList`, with matching `TabPanel`s. Accessibility: React Aria provides the
roving-tabindex and `aria-selected` wiring.

### Pagination — *Preferred*

```ts
import { PaginationLine } from "@/components/application/pagination/pagination-line";
import { PaginationDot } from "@/components/application/pagination/pagination-dot";
```

`PaginationLine` for simple prev/next, `PaginationDot` for dot indicators. The numbered
page variants (`PaginationPageDefault`, `PaginationCardDefault`,
`PaginationButtonGroup`, …) live in `@/components/application/pagination/pagination` as
building blocks.

### CommandMenu — *Variant*

```ts
import { CommandMenu } from "@/components/application/command-menus/command-menu";
```

Command palette (⌘K style) for quick actions and navigation.

### Dropdown — *Preferred*

```ts
import { Dropdown } from "@/components/base/dropdown/dropdown";
```

Base menu component. The `@/components/base/dropdown/` directory holds specialized,
pre-composed variants — import the specific file you need, e.g.:

```ts
import { DropdownButtonSimple } from "@/components/base/dropdown/dropdown-button-simple";
import { DropdownAvatar } from "@/components/base/dropdown/dropdown-avatar";
```

Other variants in that directory: `dropdown-button-advanced`, `dropdown-icon-simple`,
`dropdown-icon-advanced`, `dropdown-search-simple`, `dropdown-search-advanced`,
`dropdown-context-menu-simple`, `dropdown-context-menu-advanced`,
`dropdown-account-button`, `dropdown-account-breadcrumb`.

### App-navigation shells — *Building block*

The library ships navigation shells under
`@/components/application/app-navigation/` — the `sidebar-navigation/` directory
(`SidebarSimple`, `SidebarSlim`, `SidebarDualTier`, `SidebarSectionsSubheadings`,
`SidebarSectionDividers`, each in its own file) and `header-navigation`. **Synapse does
not use these for its app shell** — it ships its own sidebar and layout in
`@/components/layout/` (see `usage-rules.md`). Treat them as reference building blocks
only.

---

## Layout & pickers

### FilterBar — *Preferred*

```ts
import { FilterBar } from "@/components/application/filter-bar/filter-bar";
```

Row of filter controls (search, dropdowns) for list and table views. Exposed as a
compound object — compose its sub-parts.

### DatePicker / DateRangePicker — *Preferred*

```ts
import { DatePicker } from "@/components/application/date-picker/date-picker";
import { DateRangePicker } from "@/components/application/date-picker/date-range-picker";
import { Calendar } from "@/components/application/date-picker/calendar";
import { RangeCalendar } from "@/components/application/date-picker/range-calendar";
```

`DatePicker` for a single date, `DateRangePicker` for a range (with presets); `Calendar`
and `RangeCalendar` are the standalone building blocks.

### File upload — *Preferred*

```ts
import { FileUpload, FileUploadDropZone } from "@/components/application/file-upload/file-upload-base";
import { FileUploadTrigger } from "@/components/base/file-upload-trigger/file-upload-trigger";
```

`FileUpload` / `FileUploadDropZone` for a drag-and-drop zone; `FileUploadTrigger` for a
plain button that opens the file picker (no drop zone).

### Carousel — *Variant*

```ts
import { Carousel } from "@/components/application/carousel/carousel-base";
```

Horizontal scrolling carousel, exposed as a compound object (`Carousel.*`).
</content>

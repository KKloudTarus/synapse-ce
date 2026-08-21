# Component Library

> Tất cả components import từ `@/components/base/` hoặc `@/components/application/`.
> UI library: React Aria Components (Adobe). Icons: `@untitledui/icons`.

---

## Buttons

### Button

**Import:** `@/components/base/buttons/button`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"xs" \| "sm" \| "md" \| "lg" \| "xl"` | `"sm"` | Kích thước button |
| `color` | `"primary" \| "secondary" \| "tertiary" \| "link-color" \| "link-gray" \| "primary-destructive" \| "secondary-destructive" \| "tertiary-destructive" \| "link-destructive"` | `"primary"` | Màu/hierarchy |
| `iconLeading` | `FC \| ReactNode` | — | Icon trước text |
| `iconTrailing` | `FC \| ReactNode` | — | Icon sau text |
| `isDisabled` | `boolean` | — | Disabled state |
| `isLoading` | `boolean` | — | Loading spinner |
| `showTextWhileLoading` | `boolean` | — | Giữ text khi loading |
| `noTextPadding` | `boolean` | — | Bỏ px-0.5 quanh text |
| `href` | `string` | — | Render as link (anchor) |

**Design tokens:**
- Radius: `rounded-lg` (8px) cho mọi sizes
- Shadow: `shadow-xs-skeuomorphic` (primary, secondary)
- Font: `text-sm font-semibold` (xs-md), `text-md font-semibold` (lg-xl)
- Focus: `outline-2 outline-offset-2 outline-brand`

**Khi nào dùng:**
- `primary` → CTA chính, submit, confirm
- `secondary` → Action phụ (cancel, back, filter)
- `tertiary` → Action ít quan trọng (ghost button)
- `link-color` → Text link dạng brand color
- `link-gray` → Text link dạng neutral
- `primary-destructive` → Delete, remove (solid red)
- `secondary-destructive` → Delete nhẹ hơn (outline red)

---

### ButtonUtility

**Import:** `@/components/base/buttons/button-utility`

Nút icon nhỏ (close, settings, menu toggle). Không có text, chỉ icon.

---

### CloseButton

**Import:** `@/components/base/buttons/close-button`

Nút X để đóng modals, slideouts, alerts. Sử dụng `CloseX` icon.

---

### SocialButton

**Import:** `@/components/base/buttons/social-button`

Nút đăng nhập/đăng ký qua social providers (Google, Apple, GitHub...).

---

### ButtonGroup

**Import:** `@/components/base/button-group/button-group`

Nhóm buttons liền nhau (segmented control style).

---

## Inputs

### Input

**Import:** `@/components/base/input/input`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"sm" \| "md" \| "lg"` | `"md"` | Kích thước |
| `label` | `string` | — | Label phía trên |
| `hint` | `ReactNode` | — | Helper text dưới input |
| `placeholder` | `string` | — | Placeholder text |
| `icon` | `ComponentType` | — | Leading icon |
| `tooltip` | `string` | — | Help tooltip (trailing ?) |
| `shortcut` | `string \| boolean` | — | Keyboard shortcut badge |
| `isInvalid` | `boolean` | — | Error state |
| `isDisabled` | `boolean` | — | Disabled state |
| `isRequired` | `boolean` | — | Required indicator |
| `type` | `string` | `"text"` | Input type (password has toggle) |

**Design tokens:**
- Radius: `rounded-lg` (8px)
- Shadow: `shadow-xs`
- Ring: `ring-1 ring-primary` → focus: `ring-2 ring-brand`
- Error: `ring-error_subtle` → focus: `ring-2 ring-error`
- Sizes: sm = `py-2 px-3 text-sm`, md = `py-2 px-3 text-md`, lg = `py-2.5 px-3.5 text-md`

**Khi nào dùng:**
- Text input đơn giản, email, password, search
- Có label + hint cho form fields
- Có icon cho search, email icons
- Shortcut cho global search (⌘K)

---

### InputNumber / InputDate / InputFile / InputTags / InputPayment / PinInput

**Import:** `@/components/base/input/input-*`

Các biến thể chuyên biệt: số (có +/- buttons), date, file upload, tags, payment card, OTP pin.

---

### InputGroup

**Import:** `@/components/base/input/input-group`

Ghép Input + Button cạnh nhau (ví dụ: search + submit).

---

### Textarea

**Import:** `@/components/base/textarea/textarea`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"sm" \| "md"` | `"sm"` | Kích thước |
| `label` | `string` | — | Label |
| `hint` | `ReactNode` | — | Helper text |
| `isResizable` | `boolean` | — | Cho phép resize |

**Design tokens:** Giống Input (rounded-lg, shadow-xs, ring-1 ring-primary).

---

### Select

**Import:** `@/components/base/select/select`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"sm" \| "md" \| "lg"` | `"md"` | Kích thước |
| `label` | `string` | — | Label |
| `placeholder` | `string` | — | Placeholder |
| `isInvalid` | `boolean` | — | Error state |

**Biến thể khác:** `MultiSelect`, `TagSelect`, `Combobox`, `SelectNative`

**Khi nào dùng:**
- Chọn 1 option → `Select`
- Chọn nhiều options → `MultiSelect`
- Chọn với search → `Combobox`
- Chọn tags/categories → `TagSelect`
- Native select (mobile) → `SelectNative`

---

### Checkbox

**Import:** `@/components/base/checkbox/checkbox`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"sm" \| "md"` | `"sm"` | Kích thước (16px / 20px) |
| `label` | `ReactNode` | — | Label text |
| `hint` | `ReactNode` | — | Description |

**Design tokens:**
- Default: `bg-primary ring-1 ring-primary`
- Selected: `bg-brand-solid ring-brand-solid`
- Radius: sm = `rounded` (4px), md = `rounded-md` (6px)

---

### Toggle

**Import:** `@/components/base/toggle/toggle`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"sm" \| "md"` | `"sm"` | Kích thước |
| `slim` | `boolean` | — | Slim variant (thinner track) |
| `label` | `string` | — | Label text |
| `hint` | `ReactNode` | — | Description |

**Design tokens:**
- Track: `bg-tertiary` → selected: `bg-brand-solid`
- Handle: `bg-fg-white shadow-sm`, `rounded-full`
- Sizes: sm = `h-5 w-9`, md = `h-6 w-11`

**Khi nào dùng:** On/off settings, preferences, feature flags.

---

### RadioButtons

**Import:** `@/components/base/radio-buttons/radio-buttons`

Radio group cho chọn 1 trong nhiều options (exclusive selection).

---

### Slider

**Import:** `@/components/base/slider/slider`

Range slider cho numeric values.

---

## Data Display

### Badge

**Import:** `@/components/base/badges/badges`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"sm" \| "md" \| "lg"` | `"sm"` | Kích thước |
| `color` | `"gray" \| "brand" \| "error" \| "warning" \| "success" \| "slate" \| "sky" \| "blue" \| "indigo" \| "purple" \| "pink" \| "orange"` | `"gray"` | Màu |
| `type` | `"pill-color" \| "color" \| "modern"` | `"pill-color"` | Kiểu badge |
| `icon` | `IconComponentType` | — | Leading icon |
| `iconTrailing` | `IconComponentType` | — | Trailing icon |
| `dot` | `boolean` | — | Status dot |
| `avatar` | `string` | — | Avatar image |
| `flag` | `FlagTypes` | — | Country flag |
| `onDismiss` | `MouseEventHandler` | — | Close button |

**Design tokens:**
- `pill-color`: `rounded-full ring-1 ring-inset` + utility color bg/text/ring
- `color`: `rounded-md ring-1 ring-inset` + utility color bg/text/ring
- `modern`: `rounded-md ring-1 ring-inset shadow-xs` + neutral bg/text/ring

**Khi nào dùng:**
- Status indicators → `pill-color` + success/error/warning
- Categories/tags → `color` + brand/indigo/purple
- Counts/labels → `modern` + gray

---

### Avatar

**Import:** `@/components/base/avatar/avatar`

Hiển thị user avatar (image hoặc initials). Có online indicator, verified tick, company icon.

**Biến thể:** `AvatarProfilePhoto`, `AvatarLabelGroup`

---

### Tags

**Import:** `@/components/base/tags/tags`

Tag chips có thể close (x). Dùng cho filters, selected items, categories.

---

### Table

**Import:** `@/components/application/table/table`

Data table với sortable columns, selectable rows, pagination.

---

### Charts

**Import:** `@/components/application/charts/charts-base`

Chart container (wraps charting library). Bar, line, area charts.

---

### EmptyState

**Import:** `@/components/application/empty-state/empty-state`

| Compound | Mô tả |
|----------|--------|
| `EmptyState.Root` | Container (size: sm/md/lg) |
| `EmptyState.FeaturedIcon` | Icon lớn (color: gray/brand/error/success/warning) |
| `EmptyState.Illustration` | Illustration (type: cloud/files/etc) |
| `EmptyState.Header` | Title + description |
| `EmptyState.Actions` | CTA buttons |

**Khi nào dùng:** Trang trống, no results, first-time experience.

---

## Feedback

### Tooltip

**Import:** `@/components/base/tooltip/tooltip`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `title` | `ReactNode` | — | Tooltip title |
| `description` | `ReactNode` | — | Optional description |
| `placement` | `Placement` | `"top"` | Vị trí tooltip |
| `arrow` | `boolean` | `false` | Show arrow |
| `delay` | `number` | `300` | Delay (ms) |

**Design tokens:**
- Bg: `bg-primary-solid` (neutral-950)
- Radius: `rounded-lg`
- Shadow: `shadow-lg`
- Text: `text-xs font-semibold text-white`

---

### Modal / Dialog

**Import:** `@/components/application/modals/modal`

| Export | Mô tả |
|--------|--------|
| `DialogTrigger` | Trigger wrapper |
| `ModalOverlay` | Backdrop (bg-overlay/70 + backdrop-blur) |
| `Modal` | Modal container |
| `Dialog` | Content wrapper (handles scroll) |

**Design tokens:**
- Overlay: `bg-overlay/70 backdrop-blur-[6px]`
- Modal: `rounded-xl sm:rounded-2xl bg-primary shadow-xl`
- Animation: enter `300ms ease-out zoom-in-95`, exit `200ms ease-in zoom-out-95`

**Khi nào dùng:** Confirmations, forms, detail views, destructive action confirms.

---

### LoadingIndicator

**Import:** `@/components/application/loading-indicator/loading-indicator`

Spinner/skeleton cho loading states.

---

### ProgressIndicators

**Import:** `@/components/base/progress-indicators/progress-indicators`

Progress bars và circles (determinate progress). Variant: linear bar, circular.

---

## Navigation

### Tabs

**Import:** `@/components/application/tabs/tabs`

| Prop | Type | Default | Mô tả |
|------|------|---------|--------|
| `size` | `"sm" \| "md"` | `"sm"` | Kích thước |
| `type` | Horizontal: `"button-brand" \| "button-gray" \| "button-border" \| "button-minimal" \| "underline"` / Vertical: `+ "line"` | — | Style variant |
| `orientation` | `"horizontal" \| "vertical"` | `"horizontal"` | Direction |
| `fullWidth` | `boolean` | — | Full width tabs (underline) |

**Khi nào dùng:**
- `button-brand` → Primary navigation tabs
- `button-gray` → Secondary/subtle tabs
- `button-border` → Segmented control (enclosed tabs)
- `button-minimal` → Minimal tabs with ring border
- `underline` → Classic tab navigation (horizontal)
- `line` → Vertical navigation sidebar tabs

---

### Sidebar Navigation

**Import:** `@/components/application/app-navigation/sidebar-navigation/*`

| Variant | Mô tả |
|---------|--------|
| `SidebarSlim` | Collapsed icon-only sidebar |
| `SidebarSimple` | Standard sidebar với nav items |
| `SidebarDualTier` | Two-level sidebar |
| `SidebarSectionsSubheadings` | Sections with subheading groups |
| `SidebarSectionDividers` | Sections separated by dividers |

---

### Header Navigation

**Import:** `@/components/application/app-navigation/header-navigation`

Top navigation bar (logo + links + actions).

---

### Pagination

**Import:** `@/components/application/pagination/pagination`

| Variant | Mô tả |
|---------|--------|
| `Pagination` | Full pagination (numbers + prev/next) |
| `PaginationLine` | Simple prev/next |
| `PaginationDot` | Dot indicators (carousel-style) |

---

### CommandMenu

**Import:** `@/components/application/command-menus/command-menu`

Command palette (Cmd+K style). Variants: actions, users, integrations (flat + stacked).

---

## Overlay

### Dropdown

**Import:** `@/components/base/dropdown/dropdown`

| Variant | Mô tả |
|---------|--------|
| `Dropdown` | Base dropdown menu |
| `DropdownButtonSimple` | Button trigger → simple menu |
| `DropdownButtonAdvanced` | Button trigger → rich menu (icons, descriptions) |
| `DropdownIconSimple` | Icon-only trigger → simple menu |
| `DropdownIconAdvanced` | Icon-only trigger → rich menu |
| `DropdownSearchSimple` | With search filter (simple) |
| `DropdownSearchAdvanced` | With search filter (rich) |
| `DropdownContextMenuSimple` | Right-click context menu |
| `DropdownContextMenuAdvanced` | Rich context menu |
| `DropdownAvatar` | User avatar trigger → account menu |
| `DropdownAccountButton` | Account switcher |
| `DropdownAccountBreadcrumb` | Breadcrumb with dropdown |
| `DropdownIntegration` | Integration/app selector |

---

### SlideoutMenu

**Import:** `@/components/application/slideout-menus/slideout-menu`

Side panel (drawer) cho detail views, settings panels.

---

### DatePicker / DateRangePicker

**Import:** `@/components/application/date-picker/date-picker`

| Component | Mô tả |
|-----------|--------|
| `DatePicker` | Single date selection |
| `DateRangePicker` | Date range selection with presets |
| `Calendar` | Standalone calendar |
| `RangeCalendar` | Dual-month range calendar |

---

## Layout

### Carousel

**Import:** `@/components/application/carousel/carousel-base`

Horizontal scrolling carousel cho cards, images, testimonials.

---

### FilterBar

**Import:** `@/components/application/filter-bar/filter-bar`

Filter controls row (dropdowns, search) cho list/table views.

---

### FileUpload

**Import:** `@/components/application/file-upload/file-upload-base`

Drag-and-drop file upload zone.

---

### Form

**Import:** `@/components/base/form/form` / `hook-form`

Form wrapper. `hook-form` integrates with React Hook Form.

---

### FileUploadTrigger

**Import:** `@/components/base/file-upload-trigger/file-upload-trigger`

Simple button/area that triggers file picker (no drag-drop zone).

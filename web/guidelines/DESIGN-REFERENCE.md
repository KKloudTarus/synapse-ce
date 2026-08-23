# Design Reference — Global Rule (áp dụng cho TẤT CẢ specs trong 04-visual-refactor/)

## ⛔ TUYỆT ĐỐI CẤM:
- **KHÔNG XÓA/BỎ bất kỳ thành phần UI nào đang hoạt động** — tabs, buttons, inputs, form fields, panels, sections. Refactor = đổi style/tokens, KHÔNG đổi functionality. Nếu element đang render và user đang dùng → PHẢI giữ nguyên.
- KHÔNG dùng bất kỳ token/class nào từ `src/index.css` (file cũ — sẽ bị deprecate)
- KHÔNG dùng custom color vars cũ: `bg-nav`, `text-navmuted`, `border-navborder`, `bg-navactive`, `bg-navhover`, `text-navfg`, `text-navsubtle`, `bg-bg`, `bg-surface`, `bg-card`, `bg-elevated`, `text-foreground`, `text-mutedfg`, `text-subtlefg`, `border-border`, `border-borderstrong`, `bg-brand`, `text-brandfg`, etc.
- KHÔNG dùng Lucide icons — toàn bộ thay bằng `@untitledui/icons`
- KHÔNG hardcode hex colors, rgb values, hoặc magic numbers
- KHÔNG tự tạo component từ scratch nếu UUI đã có sẵn
- KHÔNG dùng custom utility classes từ index.css (`.elev`, `.card-sheen`, `.input-inset`, `.btn-primary`, `.bg-hero`, `.bg-auth`, `.lift`)

## ✅ BẮT BUỘC:

### 1. Token System — CHỈ dùng UUI theme.css tokens:
Tất cả colors phải dùng semantic tokens từ `src/styles/theme.css`:

| Category | Tokens (dùng trực tiếp như Tailwind class) |
|---|---|
| **Background** | `bg-primary`, `bg-secondary`, `bg-tertiary`, `bg-quaternary`, `bg-primary_hover`, `bg-secondary_hover`, `bg-active`, `bg-brand-solid`, `bg-brand-solid_hover`, `bg-brand-primary`, `bg-brand-secondary`, `bg-overlay`, `bg-primary-solid` |
| **Text** | `text-primary`, `text-secondary`, `text-tertiary`, `text-quaternary`, `text-placeholder`, `text-white`, `text-brand-secondary`, `text-brand-tertiary`, `text-primary_on-brand`, `text-secondary_on-brand`, `text-error-primary` |
| **Foreground (icons)** | `text-fg-primary`, `text-fg-secondary`, `text-fg-tertiary`, `text-fg-quaternary`, `text-fg-quaternary_hover`, `text-fg-brand-primary`, `text-fg-brand-secondary`, `text-fg-white`, `text-fg-error-primary`, `text-fg-success-primary`, `text-fg-warning-primary` |
| **Border** | `border-primary`, `border-secondary`, `border-tertiary`, `border-brand`, `border-error` |
| **Shadow** | `shadow-xs`, `shadow-sm`, `shadow-md`, `shadow-lg`, `shadow-xl`, `shadow-xs-skeuomorphic` |
| **Radius** | `rounded-xs`, `rounded-sm`, `rounded-md`, `rounded-lg`, `rounded-xl`, `rounded-2xl`, `rounded-3xl` |

### 2. Icons — TOÀN BỘ dùng @untitledui/icons:
```typescript
// ✅ ĐÚNG
import { Home, Settings01, Users01 } from '@untitledui/icons'

// ❌ SAI
import { Home, Settings, Users } from 'lucide-react'
```

### 3. Components — UUI FIRST:
- Trước khi tạo bất kỳ UI element nào, kiểm tra `src/components/` xem UUI có component tương ứng không
- Xem `web/guidelines/components.md` để biết import paths + props + variants
- Chỉ tạo custom component (`src/components/synapse/`) khi UUI KHÔNG có equivalent

### 4. Dark Mode:
- UUI theme.css đã có `.dark-mode` class override (dòng 700+)
- KHÔNG dùng `dark:` prefix — theme tự switch via CSS variables khi `.dark-mode` class được add
- Chỉ cần dùng đúng semantic tokens → dark mode sẽ tự hoạt động

### 5. CSS Stack (đã import sẵn qua main.tsx → globals.css):
```
src/styles/globals.css      ← Entry point: Tailwind + plugins + dark-mode variant + utilities
  └─ src/styles/theme.css   ← 856 dòng: ALL design tokens (colors, spacing, radius, shadows, typography sizes, semantic tokens + dark mode overrides)
  └─ src/styles/typography.css ← Prose/rich-text (headings, lists, code) mapped to UUI tokens
```
- `theme.css` = SOURCE OF TRUTH cho tokens (dùng class names trực tiếp: `bg-primary`, `text-secondary`, `shadow-lg`, `rounded-xl`, `text-sm`, etc.)
- `typography.css` = Tự động apply khi dùng class `.prose`
- `globals.css` = Đã setup: `@custom-variant dark (&:where(.dark-mode, .dark-mode *))` + plugins

**Đây là BỘ ĐẦY ĐỦ. Không cần thêm CSS nào khác cho UUI components hoạt động.**

## Quy tắc Stat Card (áp dụng mọi page):

Tất cả stat/KPI cards phải tuân theo layout:

```
┌─────────────────────┐
│ Label          [icon]│  ← text-sm font-semibold text-secondary (KHÔNG đậm hơn số)
│ 142                  │  ← text-3xl font-bold tabular-nums text-primary
│ Optional hint        │  ← text-xs text-tertiary
└─────────────────────┘
```

- **Label (title) NẰM TRÊN** — `text-sm font-semibold text-secondary`
- **Số (value) NẰM DƯỚI** — `text-3xl font-bold tabular-nums text-primary`
- Label in đậm (`font-semibold`) nhưng KHÔNG đậm hơn số (`font-bold`)
- Icon (optional) nằm góc phải cùng dòng label
- Card: `rounded-xl border border-secondary bg-primary p-4 shadow-xs`

---

## Quy tắc chọn design source:

1. **Nếu spec có Figma link đính kèm** → Dùng Figma MCP (`get_design_context`) để inspect design trước, extract spacing/colors/typography/layout rồi mới implement. Map Figma values về UUI theme tokens.

2. **Nếu spec KHÔNG có Figma link** → Tuân theo:
   - `src/styles/theme.css` — definitive token values
   - `web/guidelines/tokens.md` — practical token usage guide
   - `web/guidelines/components.md` — component import paths + props
   - `web/guidelines/usage-rules.md` — spacing, radius, typography conventions

3. **UUI component có sẵn** → Import và dùng. KHÔNG rebuild.

4. **Không có UUI component** → Build bằng Tailwind + UUI semantic tokens only.

## Workflow khi thực thi:

```
1. Kiểm tra UUI components available (web/guidelines/components.md)
2. Kiểm tra UUI tokens (src/styles/theme.css)
3. Has Figma link? → get_design_context() → map to UUI tokens → implement
4. No Figma link? → Follow guidelines + use default UUI styling
5. Replace ALL lucide-react imports → @untitledui/icons
6. Replace ALL custom color vars → UUI semantic tokens
7. Verify: no index.css custom vars remain in modified files
```

## Quick Reference — Mapping cũ → mới:

| Old (index.css) | New (UUI theme.css) |
|---|---|
| `bg-bg` | `bg-primary` |
| `bg-surface` | `bg-primary` |
| `bg-card` | `bg-primary` |
| `bg-elevated` | `bg-secondary` |
| `bg-nav` | `bg-primary-solid` hoặc `bg-primary` |
| `text-foreground` | `text-primary` |
| `text-mutedfg` | `text-tertiary` |
| `text-subtlefg` | `text-quaternary` |
| `border-border` | `border-secondary` |
| `border-borderstrong` | `border-primary` |
| `bg-brand` | `bg-brand-solid` |
| `text-brandfg` | `text-primary_on-brand` |
| `lucide-react` | `@untitledui/icons` |

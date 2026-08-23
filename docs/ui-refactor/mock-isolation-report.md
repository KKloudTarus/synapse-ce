# MSW Mock Isolation Verification Report

> **Date:** 2026-08-24  
> **Spec:** 04c-polish/06-msw-mock-isolation  
> **Result:** ✅ PASS (1 minor advisory)

---

## Task 1: MSW Conditional Import ✅

**File:** `web/src/main.tsx`

```tsx
async function bootstrap() {
  if (import.meta.env.DEV) {
    const { worker } = await import('./mocks/browser')
    await worker.start({ onUnhandledRequest: 'bypass' })
  }
  // ... render
}
```

- ✅ Dynamic `import('./mocks/browser')` — NOT static import at top
- ✅ Wrapped inside `import.meta.env.DEV` check
- ✅ Vite tree-shakes entire block from production build (`import.meta.env.DEV` → `false` → dead code elimination)

---

## Task 2: No Mock Imports in Page/Component Code ✅

```
grep -r "from.*mocks" src/pages/ src/components/    → 0 results
grep -r "from.*handlers" src/pages/ src/components/ → 0 results
grep -r "mockServiceWorker" src/pages/ src/components/ → 0 results
```

**Result:** ZERO mock references in application code. Clean.

---

## Task 3: Mock Data Isolation ✅

| Check | Result |
|-------|--------|
| `const MOCK_` / `const FAKE_` in `src/pages/` | 0 matches |
| `HttpResponse.json(...)` outside `src/mocks/` | 0 matches (87 matches all in `src/mocks/handlers.ts`) |
| Conditional `if (DEV) return fakeData` in `src/lib/api/` | 0 matches |

**Result:** All mock data properly isolated in `src/mocks/` directory.

---

## Task 4: Production Build Excludes MSW ✅

Build: `pnpm build` → success (2.29s)

```
grep -r "mockServiceWorker" dist/  → 0 results
grep -r "setupWorker" dist/        → 0 results
grep -l "msw" dist/assets/*.js     → 1 file (FALSE POSITIVE)
```

**False positive detail:** `EngagementDetail-C47YN1uo.js` contains `msword` in a MIME type list (`application/msword`), not MSW library code.

**Result:** MSW library code completely absent from production bundle. Tree-shaking works correctly.

---

## Task 5: Vite Proxy Behavior ✅

**File:** `web/vite.config.ts`

```ts
const apiTarget = env.VITE_API_PROXY_TARGET
// ...
...(apiTarget && {
  proxy: {
    '/api': apiTarget,
    '/healthz': apiTarget,
  },
}),
```

- ✅ Proxy only active when `VITE_API_PROXY_TARGET` is set
- ✅ Without env var → no proxy → MSW handles `/api/*` in browser
- ✅ With env var → proxy forwards to real backend
- ✅ Comment in file documents this behavior

---

## Task 6: `mockServiceWorker.js` in Production Deploy ⚠️ (Advisory)

| Check | Result |
|-------|--------|
| `web/public/mockServiceWorker.js` exists | Yes (9.7 KB) |
| Copied to `dist/` by Vite build | **Yes** — Vite copies all `public/` to `dist/` |
| `.dockerignore` excludes it | No (but Docker only builds Go backend, not frontend) |
| Deployed to S3/CloudFront via `s3 sync dist/` | **Yes** — file reaches production CDN |
| Service worker registers in production | **No** — `main.tsx` never calls `worker.start()` outside DEV |

**Impact:** LOW. The file is inert in production (never registered). However:
- It adds 9.7 KB of unnecessary weight to the CDN
- Security scanners may flag it as a test artifact in production
- It could confuse developers inspecting the deployed site

---

## Summary

| Task | Status | Notes |
|------|--------|-------|
| 1. MSW conditional import | ✅ PASS | Dynamic import + DEV guard |
| 2. No mock imports in app code | ✅ PASS | Zero references |
| 3. Mock data isolation | ✅ PASS | All in `src/mocks/` |
| 4. Production build excludes MSW | ✅ PASS | Tree-shaken completely |
| 5. Vite proxy conditional | ✅ PASS | Env-gated |
| 6. mockServiceWorker.js in deploy | ⚠️ ADVISORY | Inert but present on CDN |

---

## Recommendations

### Advisory Fix (optional, low priority)

Exclude `mockServiceWorker.js` from production deploy. One of:

**Option A** — Add to deploy workflow exclusion:
```yaml
aws s3 sync dist/ "s3://${S3_WEB_BUCKET}/" \
  --exclude "mockServiceWorker.js" \
  --delete --cache-control "public, max-age=31536000, immutable"
```

**Option B** — Move MSW worker registration to dev-only path:
```ts
// vite.config.ts
export default defineConfig({
  publicDir: mode === 'production' ? 'public-prod' : 'public',
  // ...
})
```

**Option C** — Add `.gitignore` entry and generate at dev time:
```bash
# .gitignore
public/mockServiceWorker.js

# package.json scripts
"postinstall": "npx msw init public/ --save"
```

### No action required for security

The MSW isolation is **production-safe**. The conditional `import.meta.env.DEV` guard ensures zero mock code executes in production builds.

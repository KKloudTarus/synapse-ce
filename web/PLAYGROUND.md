# Synapse playground

A static build of the dashboard that answers its own API from fixtures, so anyone can click through
the console without standing up Postgres, MinIO and the Go services. There is no backend, nothing is
scanned, no target is reached, and no request leaves the visitor's browser.

That last property is the reason the playground is static rather than a hosted instance. Synapse
executes tools against targets, so a public instance with a real backend would be an abuse vector:
someone would point it at a third party. A build with no execution path has nothing to abuse, no
credential to leak and no rate limit to enforce.

## Build

```bash
cd web
VITE_PLAYGROUND=1 pnpm build        # output: web/dist
```

`VITE_PLAYGROUND=1` changes exactly two things. The MSW worker starts in a production bundle
(normally it is dev-only), and `vite.config.ts` stops deleting `dist/mockServiceWorker.js`. That
deletion exists on purpose for normal builds: the worker is needless surface there, and a browser
holding a stale same-origin registration from a dev session would be served by it. The playground
runs on its own hostname, so neither a developer's localhost nor a customer's install is in scope.

A normal `pnpm build` is unchanged and still ships no worker. The `dist/mockServiceWorker.js` check
in the deploy step below is what catches a regression in that.

## Deploy to Cloudflare Pages

Static assets on Pages are unmetered on the free plan, and the whole site is well inside the free
limits: **185 files, 5.8 MB**, largest file 0.82 MB, against a ceiling of 20,000 files and 25 MiB per
file.

Project settings:

| Setting | Value |
| --- | --- |
| Framework preset | None |
| Root directory | `web` |
| Build command | `VITE_PLAYGROUND=1 pnpm build` |
| Build output directory | `dist` |
| Node version | 22 |

`public/_redirects` carries the SPA fallback (`/* /index.html 200`), which the dashboard needs
because it routes with `BrowserRouter`. `public/_headers` sets `nosniff`, a referrer policy,
`SAMEORIGIN` framing and `no-cache` on `index.html` and the worker, so a new deployment cannot serve
a fresh bundle against the previous fixture set. Relax `X-Frame-Options` if the playground is meant
to be embedded in a marketing page.

No Content-Security-Policy is set. One would be worth adding, and it needs to be derived from what
the bundle actually loads and verified in a browser rather than guessed, so it is left out instead of
shipped broken.

## Fixtures

Two layers, hand-written first:

1. `src/mocks/handlers.ts` holds the hand-written handlers. They are the realistic data the main
   screens are demoed with, and they take precedence over everything generated.
2. `src/mocks/generated.ts` is generated from `api/openapi.yaml` by
   `scripts/gen-playground-fixtures.py`. It answers every documented route the hand-written layer
   does not, so no screen can reach the unmocked 404 path. Values are synthesised from the response
   schema and biased by field name, and enum values that would render a module as switched off are
   avoided, because taking the first enum value gave the ownership module `mode: "off"`.

Regenerate after an API change:

```bash
cd web
python3 scripts/gen-playground-fixtures.py > src/mocks/generated.ts
```

A route the OpenAPI spec does not describe either still answers 404 and still warns on the console.
That is deliberate: it is the signal that the dashboard calls something undocumented, which is a
finding about the API rather than about the playground.

## The guided trip

`src/playground/tour-steps.ts` holds the steps. The tour is route-based rather than anchored to CSS
selectors, because the dashboard has no stable test anchors in its navigation and a selector-anchored
tour breaks silently the first time a component is restructured. A step may name an optional
`highlight` selector and still shows its card when the selector is absent.

It offers itself once per browser, and only to a visitor who landed on `/` or `/dashboard`: the tour
navigates, so auto-starting on a deep link would pull someone off the screen they were sent to.
`?tour=off` suppresses it for the whole browsing context, which is what a screenshot sweep wants.

Keyboard: left and right arrows move between steps, Escape ends the tour.

## Verifying a deployment

```bash
cd web
pnpm preview --port 4173 --host 127.0.0.1
UI_AUDIT_BASE=http://127.0.0.1:4173 UI_AUDIT_TOKEN=playground-demo \
  UI_ROUTES='["/dashboard?tour=off", ...]' pnpm ui:audit
```

`scripts/ui-audit.mjs` walks every screen in a real browser at desktop and phone width and reports
what a screenshot cannot show: console errors, failed requests, a missing page heading, horizontal
overflow, and the 404s that mean a route is unmocked. A clean sweep is the evidence that the
playground is complete; the number of screens and routes it covers is in the sweep's own output.

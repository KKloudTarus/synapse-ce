# Frontend Guidelines

These guides describe the durable conventions for building Synapse web UI with the
shared design system (Vite + React + Tailwind CSS v4). Read them before adding a page
or component so new work stays visually and behaviourally consistent with the rest of
the app.

The design system has three layers, one guide each:

- **[tokens.md](./tokens.md)** — how to choose the right design token (color, type,
  spacing, radius, shadow) for an interface. The runtime tokens themselves are defined
  in **`web/src/styles/theme.css`**, which is the single source of truth; this guide
  helps you pick among them, it does not redefine their values.
- **[components.md](./components.md)** — the shared component catalogue: what lives
  under `@/components/base/` (UI primitives) and `@/components/application/` (reusable
  application components), with copyable imports, key props, variants, and intended use.
- **[usage-rules.md](./usage-rules.md)** — how to compose those pieces into a page:
  layout and spacing you own as a page author, the canonical app shell, colour and
  dark-mode discipline, and accessibility responsibilities.

## Ground rules

- **Tokens over raw values.** Style with semantic token utilities backed by
  `theme.css`. Never hardcode hex/rgb colours or magic pixel values.
- **Reuse before building.** Check the catalogue in `components.md` first; only build a
  new component when nothing shared fits.
- **Icons come from `@untitledui/icons`.** This is the only icon set.
- **Verify both themes.** Light and dark are driven by token mappings in `theme.css`
  (see `tokens.md`); check every new surface in both.
</content>
</invoke>

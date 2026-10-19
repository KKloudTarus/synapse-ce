# Embedded PDF fonts

The report renderer embeds Liberation Sans Regular and Bold so all deployment
targets render Vietnamese text without depending on host fonts.

- Source: local `ttf-liberation` package, version `2.1.5-2`.
- `LiberationSans-Regular.ttf` SHA-256:
  `baccc64becc3eb7d104b7c84d99f5314a0a1f896e2b3ea6c2f22fc08d2003bee`
- `LiberationSans-Bold.ttf` SHA-256:
  `769673c4355020b1e28a14c366a152da410ab6b16239fe883ebc35b73624835b`
- License: SIL Open Font License 1.1, included in
  `LiberationSans-LICENSE.txt` with trailing whitespace normalized.

Both font files contain the Vietnamese U+1EA0–U+1EF9 range. `fonts_test.go`
parses their cmap tables and verifies every rune exercised by the PDF
acceptance text before it renders either report path.

Release archives include the notice under `LICENSES/`. Control-plane and CLI
images and native worker packages include it under
`/usr/share/licenses/synapse-ce/`. The font bytes match the installed package
metadata; no independent upstream signature verification is claimed.

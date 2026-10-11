// Package eventschemas embeds the published notification event fixtures, so the template preview
// (#1372) renders against the same payloads the schemas document and the builder golden tests pin.
package eventschemas

import "embed"

// Fixtures holds one `<event type>.v1.fixture.json` envelope per catalog event type.
//
//go:embed *.fixture.json
var Fixtures embed.FS

package report

import (
	_ "embed"
	"fmt"
	"time"

	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core/entity"
	"github.com/johnfercher/maroto/v2/pkg/fontrepository"
	"github.com/johnfercher/maroto/v2/pkg/props"
)

const reportFontFamily = "LiberationSans"

// Liberation Sans 2.1.5, supplied by the local ttf-liberation 2.1.5-2
// package and embedded under the SIL Open Font License 1.1. The exact license
// and source checksums are retained in assets/README.md.
//
//go:embed assets/LiberationSans-Regular.ttf
var reportRegularFont []byte

//go:embed assets/LiberationSans-Bold.ttf
var reportBoldFont []byte

// documentConfig embeds fonts with Vietnamese glyph coverage for every PDF
// render. A new repository is created per document so the renderer has no
// mutable shared font state and remains deterministic under concurrent use.
func documentConfig(createdAt time.Time) (*entity.Config, error) {
	fonts, err := fontrepository.New().
		AddUTF8FontFromBytes(reportFontFamily, fontstyle.Normal, reportRegularFont).
		AddUTF8FontFromBytes(reportFontFamily, fontstyle.Bold, reportBoldFont).
		Load()
	if err != nil {
		return nil, fmt.Errorf("load PDF fonts: %w", err)
	}
	return config.NewBuilder().
		WithCreationDate(createdAt).
		WithCustomFonts(fonts).
		WithDefaultFont(&props.Font{Family: reportFontFamily}).
		Build(), nil
}

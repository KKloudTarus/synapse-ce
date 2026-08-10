package projectuc

import "github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"

func persistedSourceFileForRead(analysis projectanalysis.Analysis, path string, base bool) (projectanalysis.SourceFile, bool) {
	manifest := analysis.SourceManifest
	if base {
		manifest = analysis.Comparison.BaseManifest
	}
	for _, file := range manifest.Files {
		if file.Path == path {
			return file, true
		}
	}
	return projectanalysis.SourceFile{}, false
}

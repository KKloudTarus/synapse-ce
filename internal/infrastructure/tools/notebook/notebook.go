// Package notebook decodes the small, stable subset of the Jupyter notebook format needed by source analyzers.
package notebook

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Cell is one notebook cell. Index is 1-based in the original cells array, so a finding remains stable
// when markdown/raw cells surround code.
type Cell struct {
	Index          int
	Type           string
	Source         string
	Output         string
	Traceback      string
	HasOutput      bool
	ExecutionCount *int
}

// Document contains the decoded notebook data that analysis needs.
type Document struct {
	Cells          []Cell
	HasKernelspec  bool
	KernelLanguage string
}

type source string

func (s *source) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*s = source(text)
		return nil
	}
	var parts []string
	if err := json.Unmarshal(data, &parts); err != nil {
		return err
	}
	*s = source(strings.Join(parts, ""))
	return nil
}

type rawCell struct {
	Type           string            `json:"cell_type"`
	Source         source            `json:"source"`
	Outputs        []json.RawMessage `json:"outputs"`
	ExecutionCount *int              `json:"execution_count"`
}

type rawNotebook struct {
	Cells    []rawCell       `json:"cells"`
	Metadata json.RawMessage `json:"metadata"`
}

// Parse decodes a notebook without executing or interpreting its code. Output is deliberately text-only:
// it collects textual MIME payloads and ignores binary payloads.
func Parse(data []byte) (Document, error) {
	var raw rawNotebook
	if err := json.Unmarshal(data, &raw); err != nil {
		return Document{}, err
	}
	kernelLanguage, hasKernelspec := kernelspec(raw.Metadata)
	doc := Document{Cells: make([]Cell, 0, len(raw.Cells)), HasKernelspec: hasKernelspec, KernelLanguage: kernelLanguage}
	for i, cell := range raw.Cells {
		var output, traceback strings.Builder
		for _, value := range cell.Outputs {
			output.WriteString(outputText(value))
			traceback.WriteString(tracebackText(value))
		}
		doc.Cells = append(doc.Cells, Cell{
			Index: i + 1, Type: cell.Type, Source: string(cell.Source), Output: output.String(), Traceback: traceback.String(), HasOutput: len(cell.Outputs) > 0, ExecutionCount: cell.ExecutionCount,
		})
	}
	return doc, nil
}

func kernelspec(raw json.RawMessage) (string, bool) {
	var metadata struct {
		Kernelspec struct {
			Name     string `json:"name"`
			Language string `json:"language"`
		} `json:"kernelspec"`
		LanguageInfo struct {
			Name string `json:"name"`
		} `json:"language_info"`
	}
	if json.Unmarshal(raw, &metadata) != nil {
		return "", false
	}
	language := strings.TrimSpace(metadata.LanguageInfo.Name)
	if language == "" {
		language = strings.TrimSpace(metadata.Kernelspec.Language)
	}
	if language == "" && strings.EqualFold(strings.TrimSpace(metadata.Kernelspec.Name), "python3") {
		language = "python"
	}
	return language, strings.TrimSpace(metadata.Kernelspec.Name) != ""
}

func tracebackText(raw json.RawMessage) string {
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	var out strings.Builder
	appendStrings(&out, value["traceback"])
	return out.String()
}

func outputText(raw json.RawMessage) string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	var out strings.Builder
	appendStrings(&out, value)
	return out.String()
}

func appendStrings(out *strings.Builder, value any) {
	switch v := value.(type) {
	case string:
		out.WriteString(v)
	case []any:
		for _, item := range v {
			appendStrings(out, item)
		}
	case map[string]any:
		for _, key := range []string{"text", "traceback", "evalue"} {
			if item, ok := v[key]; ok {
				appendStrings(out, item)
			}
		}
		if data, ok := v["data"].(map[string]any); ok {
			for mime, item := range data {
				if mime == "application/json" {
					appendJSONStrings(out, item)
				} else if strings.HasPrefix(mime, "text/") || mime == "image/svg+xml" {
					appendStrings(out, item)
				}
			}
		}
	}
}

func appendJSONStrings(out *strings.Builder, value any) {
	switch v := value.(type) {
	case string:
		out.WriteString(v)
	case []any:
		for _, item := range v {
			appendJSONStrings(out, item)
		}
	case map[string]any:
		for key, item := range v {
			out.WriteString(key)
			out.WriteByte(':')
			if text, ok := item.(string); ok {
				out.WriteString(strconv.Quote(text))
				continue
			}
			appendJSONStrings(out, item)
		}
	}
}

// IsPath reports whether path names an IPython notebook.
func IsPath(path string) bool { return strings.HasSuffix(strings.ToLower(path), ".ipynb") }

// Location returns the stable finding identity for a cell inside a notebook.
func Location(rel string, index int) string { return rel + "#cell-" + strconv.Itoa(index) }

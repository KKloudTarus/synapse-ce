package messageformat

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const maxJiraTableDescriptionBytes = 48 << 10

func jiraTableCells(headers []string, rows [][]string) ([][]string, error) {
	if len(headers) == 0 || len(headers) > 6 || len(rows) == 0 || len(rows) > 100 {
		return nil, fmt.Errorf("%w: Jira asset table bounds exceeded", shared.ErrValidation)
	}
	all := make([][]string, 0, len(rows)+1)
	all = append(all, headers)
	all = append(all, rows...)
	result := make([][]string, len(all))
	total := 0
	for i, row := range all {
		if len(row) != len(headers) {
			return nil, fmt.Errorf("%w: invalid Jira asset table shape", shared.ErrValidation)
		}
		result[i] = make([]string, len(row))
		for j, cell := range row {
			if !utf8.ValidString(cell) || len(cell) > 1024 {
				return nil, fmt.Errorf("%w: Jira asset table cell bounds exceeded", shared.ErrValidation)
			}
			total += len(cell)
			if total > 16<<10 {
				return nil, fmt.Errorf("%w: Jira asset table bounds exceeded", shared.ErrValidation)
			}
			// A cell cannot introduce another wiki row or a markup control character.
			result[i][j] = strings.Map(func(r rune) rune {
				if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
					return ' '
				}
				return r
			}, cell)
		}
	}
	return result, nil
}

// JiraADFWithTable keeps all supplied cells in literal ADF text nodes.
func JiraADFWithTable(body string, links []ports.RenderedLink, headers []string, rows [][]string) (map[string]any, error) {
	cells, err := jiraTableCells(headers, rows)
	if err != nil {
		return nil, err
	}
	doc, err := JiraADF(body, links)
	if err != nil {
		return nil, err
	}
	tableRows := make([]any, 0, len(cells))
	for i, row := range cells {
		kind := "tableCell"
		if i == 0 {
			kind = "tableHeader"
		}
		tableCells := make([]any, 0, len(row))
		for _, cell := range row {
			var text []any
			if cell != "" {
				text = []any{adfText(cell, nil)}
			}
			tableCells = append(tableCells, map[string]any{"type": kind, "content": []any{adfParagraph(text)}})
		}
		tableRows = append(tableRows, map[string]any{"type": "tableRow", "content": tableCells})
	}
	doc["content"] = append(doc["content"].([]any), map[string]any{"type": "table", "attrs": map[string]any{"layout": "default", "isNumberColumnEnabled": false}, "content": tableRows})
	raw, err := json.Marshal(doc)
	if err != nil || len(raw) > maxJiraTableDescriptionBytes {
		return nil, fmt.Errorf("%w: Jira group description bounds exceeded", shared.ErrValidation)
	}
	return doc, nil
}

// JiraWikiWithTable introduces table delimiters only around escaped cells.
func JiraWikiWithTable(body string, links []ports.RenderedLink, headers []string, rows [][]string) (string, error) {
	cells, err := jiraTableCells(headers, rows)
	if err != nil {
		return "", err
	}
	base, err := JiraWiki(body, links)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString(base)
	out.WriteString("\n\n")
	for i, row := range cells {
		delimiter := "|"
		if i == 0 {
			delimiter = "||"
		}
		out.WriteString(delimiter)
		for _, cell := range row {
			out.WriteString(escapeWiki(cell))
			out.WriteString(delimiter)
		}
		if i < len(cells)-1 {
			out.WriteByte('\n')
		}
	}
	if out.Len() > maxJiraTableDescriptionBytes {
		return "", fmt.Errorf("%w: Jira group description bounds exceeded", shared.ErrValidation)
	}
	return out.String(), nil
}

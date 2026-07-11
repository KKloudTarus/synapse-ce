// Package measure holds numeric, non-finding project measures (code size, complexity, duplication,
// coverage). It is the counterpart to domain/finding for the code-quality ("power tool") capability:
// a finding is a defect to fix, a measure is a number that describes the codebase. Pure domain – data
// types + deterministic rollups only, no I/O and no infrastructure types.
package measure

import "sort"

// LanguageInventory is the code-size inventory for one detected programming/markup language over a
// source tree. Line counts are exact; Functions is exact only for languages with a first-party parser
// (Go today) and is 0 where accurate function counting is not yet available (the multi-language AST
// phase fills the rest), so a 0 means "not counted", never "zero functions found".
type LanguageInventory struct {
	Language       string `json:"language"`
	Files          int    `json:"files"`
	CodeLines      int    `json:"code_lines"`
	CommentLines   int    `json:"comment_lines"`
	BlankLines     int    `json:"blank_lines"`
	Functions      int    `json:"functions"`
	FunctionsKnown bool   `json:"functions_known"` // whether Functions is an accurate count for this language
}

// TotalLines is the sum of code, comment and blank lines.
func (li LanguageInventory) TotalLines() int { return li.CodeLines + li.CommentLines + li.BlankLines }

// Inventory is a per-language code inventory over a source tree, sorted deterministically by language.
type Inventory struct {
	Languages []LanguageInventory `json:"languages"`
}

// NewInventory builds a sorted Inventory from a per-language accumulation map. Sorting by language name
// keeps the output stable across runs (Go randomizes map iteration).
func NewInventory(byLang map[string]LanguageInventory) Inventory {
	langs := make([]LanguageInventory, 0, len(byLang))
	for _, li := range byLang {
		langs = append(langs, li)
	}
	sort.Slice(langs, func(i, j int) bool { return langs[i].Language < langs[j].Language })
	return Inventory{Languages: langs}
}

// Totals sums the per-language counts into a single row labelled "TOTAL". FunctionsKnown is true only
// when every language with functions had an accurate count, so the total is not silently understated.
func (inv Inventory) Totals() LanguageInventory {
	t := LanguageInventory{Language: "TOTAL", FunctionsKnown: true}
	for _, li := range inv.Languages {
		t.Files += li.Files
		t.CodeLines += li.CodeLines
		t.CommentLines += li.CommentLines
		t.BlankLines += li.BlankLines
		t.Functions += li.Functions
		if !li.FunctionsKnown {
			t.FunctionsKnown = false
		}
	}
	return t
}

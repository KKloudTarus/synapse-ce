package jsimports

import (
	"context"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type ViteAlias struct {
	Find        string
	Replacement string
}

func ObserveViteAliases(ctx context.Context, src []byte) ([]ViteAlias, bool, error) {
	if ctx == nil {
		return nil, false, fmt.Errorf("%w: source alias observation requires a context", shared.ErrValidation)
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if len(src) > int(defaultMaxFileBytes) || !utf8.Valid(src) {
		return nil, false, nil
	}
	e := newExtractor(src, false)
	defineConfig := make(map[string]bool)
	for e.peek().text == "import" {
		e.handleImportKeyword(e.next(), token{}, false)
		if len(e.out.imports) == 0 {
			return nil, false, nil
		}
		imp := e.out.imports[len(e.out.imports)-1]
		if imp.specifier != "vite" || imp.kind != modulegraph.ImportESMStatic || imp.typeOnly {
			return nil, false, nil
		}
		for _, binding := range imp.bindings {
			if binding.Imported == "defineConfig" {
				defineConfig[binding.Local] = true
			}
		}
		if e.peek().text == ";" {
			e.next()
		}
	}
	if e.next().text != "export" || e.next().text != "default" {
		return nil, false, nil
	}
	wrapped := false
	if t := e.peek(); t.kind == tokenIdent && defineConfig[t.text] {
		e.next()
		if e.next().text != "(" {
			return nil, false, nil
		}
		wrapped = true
	}
	if e.next().text != "{" {
		return nil, false, nil
	}
	var aliases []ViteAlias
	seenResolve := false
	for e.peek().text != "}" {
		if t := e.next(); (t.kind != tokenIdent && t.kind != tokenString) || t.text != "resolve" || seenResolve || e.next().text != ":" || e.next().text != "{" {
			return nil, false, nil
		}
		seenResolve = true
		if e.peek().text != "}" {
			if t := e.next(); (t.kind != tokenIdent && t.kind != tokenString) || t.text != "alias" || e.next().text != ":" || e.next().text != "{" {
				return nil, false, nil
			}
			seen := make(map[string]bool)
			for e.peek().text != "}" {
				find := e.next()
				if (find.kind != tokenString && find.kind != tokenIdent) || find.text == "" || find.text == "__proto__" || find.undecodedEscape || seen[find.text] || e.next().text != ":" {
					return nil, false, nil
				}
				if _, err := strconv.ParseUint(find.text, 10, 32); err == nil {
					return nil, false, nil
				}
				replacement := e.next()
				if replacement.kind != tokenString || replacement.undecodedEscape {
					return nil, false, nil
				}
				seen[find.text] = true
				if len(aliases) >= 64 {
					return nil, false, nil
				}
				aliases = append(aliases, ViteAlias{Find: find.text, Replacement: replacement.text})
				if e.peek().text != "," {
					break
				}
				e.next()
			}
			if e.next().text != "}" {
				return nil, false, nil
			}
			if e.peek().text == "," {
				e.next()
			}
		}
		if e.next().text != "}" {
			return nil, false, nil
		}
		if e.peek().text != "," {
			break
		}
		e.next()
	}
	if e.next().text != "}" {
		return nil, false, nil
	}
	if wrapped && e.next().text != ")" {
		return nil, false, nil
	}
	if e.peek().text == ";" {
		e.next()
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return aliases, e.next().kind == tokenEOF && len(e.out.hazards) == 0 && len(e.lex.hazards) == 0, nil
}

package msgtemplate

import "errors"

// Data is the render context: flat strings plus lists of flat string maps. Keys not declared in the
// Schema are dropped, declared keys that are absent render as empty strings, values longer than the
// schema's MaxValueRunes are cut, and lists are cut to their declared cap.
type Data struct {
	Vars  map[string]string
	Lists map[string][]map[string]string
}

// Output is one rendered field. Truncated reports that the maxRunes cap passed to Render cut the
// output; a truncate call inside the template is the author's choice and does not set it.
type Output struct {
	Text      string
	Truncated bool
}

// Render executes the template. maxRunes caps the output; a longer result is cut, ends with an
// ellipsis and sets Truncated, and never fails the render. Errors carry a code and never a value:
// ErrRender for a runtime value the template cannot use (for example a non-numeric count passed to
// plural), ErrUsage for a maxRunes out of range.
func (t *Template) Render(data Data, maxRunes int) (Output, error) {
	if maxRunes < 1 || maxRunes > MaxOutputRunes {
		return Output{}, usageError(CodeInvalidLimit)
	}
	tmpl, err := t.tmpl.Clone()
	if err != nil {
		return Output{}, renderError(CodeRenderFailed)
	}
	tmpl.Funcs(funcMap(&meter{}))
	w := &limitWriter{max: maxRunes}
	if err := tmpl.Execute(w, t.context(data)); err != nil && !errors.Is(err, errOutputLimit) {
		return Output{}, renderError(renderCode(err))
	}
	return w.output(), nil
}

func renderCode(err error) Code {
	switch {
	case errors.Is(err, errArgument):
		return CodeInvalidArgument
	case errors.Is(err, errBudget):
		return CodeRenderBudgetExceeded
	}
	return CodeRenderFailed
}

// context shapes data to the schema. The result holds only unnamed map and slice types with string
// values, so a template has no method to reach.
func (t *Template) context(data Data) map[string]any {
	values := make(map[string]any, len(t.schema.vars)+len(t.schema.lists))
	for name := range t.schema.vars {
		values[name] = truncateRunes(data.Vars[name], t.schema.maxValueRunes)
	}
	for name, list := range t.schema.lists {
		values[name] = t.listContext(data.Lists[name], list)
	}
	return values
}

func (t *Template) listContext(source []map[string]string, list schemaList) []map[string]string {
	items := make([]map[string]string, min(len(source), list.cap))
	for i := range items {
		item := make(map[string]string, len(list.fields))
		for field := range list.fields {
			item[field] = truncateRunes(source[i][field], t.schema.maxValueRunes)
		}
		items[i] = item
	}
	return items
}

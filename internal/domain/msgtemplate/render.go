package msgtemplate

import "errors"

// Data is the render context: flat strings plus lists of flat string maps. Keys not declared in the
// Schema are dropped, declared keys that are absent render as empty strings, and lists are cut to
// their declared cap.
type Data struct {
	Vars  map[string]string
	Lists map[string][]map[string]string
}

// Output is one rendered field.
type Output struct {
	Text      string
	Truncated bool
}

// Render executes the template. maxRunes caps the output; a longer result is cut, ends with an
// ellipsis and sets Truncated, and never fails the render. A compiled template can still fail on a
// runtime value, for example a non-numeric count passed to plural; the error carries a code and
// never a value.
func (t *Template) Render(data Data, maxRunes int) (Output, error) {
	if maxRunes < 1 || maxRunes > MaxOutputRunes {
		return Output{}, renderError(CodeInvalidLimit)
	}
	w := &limitWriter{max: maxRunes}
	if err := t.tmpl.Execute(w, t.context(data)); err != nil && !errors.Is(err, errOutputLimit) {
		if errors.Is(err, errArgument) {
			return Output{}, renderError(CodeInvalidArgument)
		}
		return Output{}, renderError(CodeRenderFailed)
	}
	return w.output(), nil
}

// context shapes data to the schema. The result holds only unnamed map and slice types with string
// values, so a template has no method to reach.
func (t *Template) context(data Data) map[string]any {
	values := make(map[string]any, len(t.schema.vars)+len(t.schema.lists))
	for name := range t.schema.vars {
		values[name] = data.Vars[name]
	}
	for name, list := range t.schema.lists {
		values[name] = listContext(data.Lists[name], list)
	}
	return values
}

func listContext(source []map[string]string, list compiledList) []map[string]string {
	items := make([]map[string]string, min(len(source), list.cap))
	for i := range items {
		item := make(map[string]string, len(list.fields))
		for field := range list.fields {
			item[field] = source[i][field]
		}
		items[i] = item
	}
	return items
}

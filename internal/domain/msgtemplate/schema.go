package msgtemplate

import "sort"

// Schema declares every variable a template may reference. The notification event catalog and the
// ticket context spec each build one; this package imports neither.
//
// Scalars are plain strings. A list is a slice of flat string maps whose keys are Fields; Cap bounds
// both the static iteration cost and the number of items Render will pass to the template.
type Schema struct {
	Vars  []string
	Lists map[string]List
}

// List declares one list variable.
type List struct {
	Cap    int
	Fields []string
}

type compiledList struct {
	cap    int
	fields map[string]bool
}

type compiledSchema struct {
	vars  map[string]bool
	lists map[string]compiledList
}

func compileSchema(s Schema) (compiledSchema, error) {
	out := compiledSchema{vars: map[string]bool{}, lists: map[string]compiledList{}}
	for _, name := range s.Vars {
		if !validName(name) || out.vars[name] {
			return compiledSchema{}, &Error{Code: CodeInvalidSchema, Detail: name}
		}
		out.vars[name] = true
	}
	names := make([]string, 0, len(s.Lists))
	for name := range s.Lists {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		list := s.Lists[name]
		if !validName(name) || out.vars[name] || list.Cap < 1 || list.Cap > MaxIterationProduct || len(list.Fields) == 0 {
			return compiledSchema{}, &Error{Code: CodeInvalidSchema, Detail: name}
		}
		fields := make(map[string]bool, len(list.Fields))
		for _, field := range list.Fields {
			if !validName(field) || fields[field] {
				return compiledSchema{}, &Error{Code: CodeInvalidSchema, Detail: name + "." + field}
			}
			fields[field] = true
		}
		out.lists[name] = compiledList{cap: list.Cap, fields: fields}
	}
	return out, nil
}

// validName accepts lower snake case, which is also a valid text/template field name.
func validName(name string) bool {
	if name == "" || len(name) > 64 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

package jsresolve

import (
	"bytes"
	"fmt"
)

func sanitizeJSONC(in []byte) ([]byte, error) {
	if bytes.HasPrefix(in, []byte{0xef, 0xbb, 0xbf}) {
		in = in[3:]
	}
	withoutComments := make([]byte, 0, len(in))
	inString := false
	escaped := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inString {
			withoutComments = append(withoutComments, c)
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			withoutComments = append(withoutComments, c)
			continue
		}
		if c == '/' && i+1 < len(in) {
			switch in[i+1] {
			case '/':
				withoutComments = append(withoutComments, ' ', ' ')
				i += 2
				for ; i < len(in) && in[i] != '\n'; i++ {
					withoutComments = append(withoutComments, ' ')
				}
				if i < len(in) {
					withoutComments = append(withoutComments, '\n')
				}
				continue
			case '*':
				withoutComments = append(withoutComments, ' ', ' ')
				i += 2
				closed := false
				for ; i < len(in); i++ {
					if i+1 < len(in) && in[i] == '*' && in[i+1] == '/' {
						withoutComments = append(withoutComments, ' ', ' ')
						i++
						closed = true
						break
					}
					if in[i] == '\n' {
						withoutComments = append(withoutComments, '\n')
					} else {
						withoutComments = append(withoutComments, ' ')
					}
				}
				if !closed {
					return nil, fmt.Errorf("unterminated block comment in tsconfig/jsconfig")
				}
				continue
			}
		}
		withoutComments = append(withoutComments, c)
	}
	if inString {
		return nil, fmt.Errorf("unterminated string in tsconfig/jsconfig")
	}

	out := make([]byte, 0, len(withoutComments))
	inString = false
	escaped = false
	for i := 0; i < len(withoutComments); i++ {
		c := withoutComments[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(withoutComments) && (withoutComments[j] == ' ' || withoutComments[j] == '\t' || withoutComments[j] == '\r' || withoutComments[j] == '\n') {
				j++
			}
			if j < len(withoutComments) && (withoutComments[j] == '}' || withoutComments[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out, nil
}

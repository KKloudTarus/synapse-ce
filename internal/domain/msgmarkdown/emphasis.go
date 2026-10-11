package msgmarkdown

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// This file resolves emphasis with the CommonMark 0.31 delimiter-run algorithm ("process
// emphasis"), restricted to "*" and "_" because the subset has no links or images.

type elementKind int

const (
	textElement elementKind = iota
	delimiterElement
	nodeElement
)

// element is one item of the inline sequence while emphasis is resolved. A delimiter element is a
// run of "*" or "_" that may still open or close emphasis; count shrinks as it is used.
type element struct {
	kind       elementKind
	text       string
	node       Inline
	char       byte
	count      int
	original   int
	canOpen    bool
	canClose   bool
	prev, next *element
}

type elementList struct{ head, tail *element }

func (l *elementList) push(e *element) {
	e.prev = l.tail
	if l.tail != nil {
		l.tail.next = e
	} else {
		l.head = e
	}
	l.tail = e
}

func (l *elementList) remove(e *element) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		l.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (l *elementList) insertAfter(at, e *element) {
	e.prev, e.next = at, at.next
	if at.next != nil {
		at.next.prev = e
	} else {
		l.tail = e
	}
	at.next = e
}

// newDelimiter classifies the run text[start:end] as left- and/or right-flanking from the
// characters around it, and derives whether it can open and close emphasis.
func newDelimiter(text string, start, end int) *element {
	before, after := ' ', ' ' // the start and end of the text count as whitespace
	if start > 0 {
		before, _ = utf8.DecodeLastRuneInString(text[:start])
	}
	if end < len(text) {
		after, _ = utf8.DecodeRuneInString(text[end:])
	}
	leftFlanking := !unicode.IsSpace(after) && (!isPunctuation(after) || unicode.IsSpace(before) || isPunctuation(before))
	rightFlanking := !unicode.IsSpace(before) && (!isPunctuation(before) || unicode.IsSpace(after) || isPunctuation(after))
	d := &element{kind: delimiterElement, char: text[start], count: end - start, original: end - start}
	if d.char == '*' {
		d.canOpen, d.canClose = leftFlanking, rightFlanking
	} else {
		d.canOpen = leftFlanking && (!rightFlanking || isPunctuation(before))
		d.canClose = rightFlanking && (!leftFlanking || isPunctuation(after))
	}
	return d
}

// isPunctuation is the CommonMark definition: an ASCII punctuation character or a Unicode
// punctuation (P) or symbol (S) character.
func isPunctuation(r rune) bool {
	if r < utf8.RuneSelf {
		return strings.ContainsRune(asciiPunctuation, r)
	}
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}

type openerKey struct {
	char     byte
	canOpen  bool
	modThree int
}

// processEmphasis matches closers with the nearest eligible opener, wrapping what lies between
// them in Strong (two characters used) or Emphasis (one character used).
func processEmphasis(list *elementList) {
	openersBottom := map[openerKey]*element{}
	for closer := nextDelimiter(list.head); closer != nil; {
		if !closer.canClose {
			closer = nextDelimiter(closer.next)
			continue
		}
		key := openerKey{closer.char, closer.canOpen, closer.original % 3}
		opener := findOpener(closer, openersBottom[key])
		if opener == nil {
			openersBottom[key] = closer.prev
			next := nextDelimiter(closer.next)
			if !closer.canOpen {
				closer.kind = textElement
			}
			closer = next
			continue
		}
		used := 1
		if opener.count >= 2 && closer.count >= 2 {
			used = 2
		}
		opener.count -= used
		closer.count -= used
		wrapBetween(list, opener, closer, used)
		if opener.count == 0 {
			list.remove(opener)
		}
		if closer.count == 0 {
			next := nextDelimiter(closer.next)
			list.remove(closer)
			closer = next
		}
	}
}

// findOpener walks back from closer, stopping at bottom, for a delimiter that can open a match
// with it. The "rule of three" refuses a match when either run can both open and close and the sum
// of the original lengths is a multiple of 3, unless both lengths are.
func findOpener(closer, bottom *element) *element {
	for e := closer.prev; e != nil && e != bottom; e = e.prev {
		if e.kind != delimiterElement || e.char != closer.char || !e.canOpen {
			continue
		}
		if (e.canClose || closer.canOpen) && (e.original+closer.original)%3 == 0 && (e.original%3 != 0 || closer.original%3 != 0) {
			continue
		}
		return e
	}
	return nil
}

// wrapBetween replaces the elements strictly between opener and closer with one node holding them.
// Unmatched delimiters inside become literal text.
func wrapBetween(list *elementList, opener, closer *element, used int) {
	children := list.inlines(opener.next, closer)
	for e := opener.next; e != closer; {
		next := e.next
		list.remove(e)
		e = next
	}
	var node Inline = Emphasis{Children: children}
	if used == 2 {
		node = Strong{Children: children}
	}
	list.insertAfter(opener, &element{kind: nodeElement, node: node})
}

func nextDelimiter(e *element) *element {
	for ; e != nil; e = e.next {
		if e.kind == delimiterElement {
			return e
		}
	}
	return nil
}

// inlines converts the elements from start up to, not including, stop into inline nodes. Adjacent
// literal text, including leftover delimiter characters, is merged into one Text.
func (l *elementList) inlines(start, stop *element) []Inline {
	var out []Inline
	var literal strings.Builder
	flush := func() {
		if literal.Len() > 0 {
			out = append(out, Text{Value: literal.String()})
			literal.Reset()
		}
	}
	for e := start; e != stop && e != nil; e = e.next {
		switch e.kind {
		case textElement:
			if e.char != 0 {
				literal.WriteString(strings.Repeat(string(e.char), e.count))
			} else {
				literal.WriteString(e.text)
			}
		case delimiterElement:
			literal.WriteString(strings.Repeat(string(e.char), e.count))
		case nodeElement:
			flush()
			out = append(out, e.node)
		}
	}
	flush()
	return out
}

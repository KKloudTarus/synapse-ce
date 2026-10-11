package msgmarkdown

// Document is a parsed message body.
type Document struct {
	Blocks []Block
}

// Block is a Paragraph or a List.
type Block interface{ block() }

// Paragraph is a run of inline content. Line breaks inside it are LineBreak inlines.
type Paragraph struct {
	Inlines []Inline
}

// List is a single-level bullet list; each item is one run of inline content.
type List struct {
	Items [][]Inline
}

func (Paragraph) block() {}
func (List) block()      {}

// Inline is Text, Strong, Emphasis, Code, LineBreak or Link.
type Inline interface{ inline() }

// Text is literal text: every character is shown as is.
type Text struct {
	Value string
}

// Strong is strong emphasis (bold).
type Strong struct {
	Children []Inline
}

// Emphasis is emphasis (italic).
type Emphasis struct {
	Children []Inline
}

// Code is an inline code span; its value is literal.
type Code struct {
	Value string
}

// LineBreak is a line break inside a paragraph.
type LineBreak struct{}

// Link is a typed link. The parser never produces one: links come from the server-side link
// builder and are placed by the formatter, so a value or a template can never forge one.
type Link struct {
	Label string
	URL   string
}

func (Text) inline()      {}
func (Strong) inline()    {}
func (Emphasis) inline()  {}
func (Code) inline()      {}
func (LineBreak) inline() {}
func (Link) inline()      {}

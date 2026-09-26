package msgtemplate

import (
	"errors"
	"strconv"
	"strings"
)

// Code identifies why a template was rejected or failed to render. Codes are stable API values:
// the console maps them to messages, so they are never renamed.
type Code string

// Schema and source rejections.
const (
	CodeInvalidSchema      Code = "invalid_schema"
	CodeInvalidName        Code = "invalid_name"
	CodeSourceTooLarge     Code = "source_too_large"
	CodeInvalidEncoding    Code = "invalid_encoding"
	CodeForbiddenCharacter Code = "forbidden_character"
	CodeParse              Code = "parse_error"
	CodeEmptyTemplate      Code = "empty_template"
	CodeDanglingEscape     Code = "dangling_escape"
)

// Structural rejections from the tree walk.
const (
	CodeForbiddenDefine       Code = "forbidden_define"
	CodeForbiddenTemplateCall Code = "forbidden_template_call"
	CodeForbiddenNode         Code = "forbidden_node"
	CodeForbiddenFunction     Code = "forbidden_function"
	CodeForbiddenDeclaration  Code = "forbidden_declaration"
	CodeForbiddenAssignment   Code = "forbidden_assignment"
	CodeInvalidPipeline       Code = "invalid_pipeline"
	CodeInvalidRange          Code = "invalid_range"
	CodeDotOutsideScope       Code = "dot_outside_scope"
)

// Reference and type rejections.
const (
	CodeUnknownVariable    Code = "unknown_variable"
	CodeUnknownField       Code = "unknown_field"
	CodeInvalidField       Code = "invalid_field"
	CodeInvalidVariable    Code = "invalid_variable"
	CodeListMisuse         Code = "list_misuse"
	CodeWrongArgumentCount Code = "wrong_argument_count"
	CodeArgumentType       Code = "argument_type"
)

// Cost rejections.
const (
	CodeTooManyNodes           Code = "too_many_nodes"
	CodeNestingTooDeep         Code = "nesting_too_deep"
	CodeRangeNestingTooDeep    Code = "range_nesting_too_deep"
	CodeIterationBoundExceeded Code = "iteration_bound_exceeded"
	CodeCostBoundExceeded      Code = "cost_bound_exceeded"
)

// Render failures.
const (
	CodeInvalidLimit    Code = "invalid_limit"
	CodeInvalidArgument Code = "invalid_argument"
	CodeRenderFailed    Code = "render_failed"
)

var (
	// ErrInvalidTemplate wraps every compile-time rejection.
	ErrInvalidTemplate = errors.New("msgtemplate: invalid template")
	// ErrRender wraps every render-time failure.
	ErrRender = errors.New("msgtemplate: render failed")
)

// Error describes a rejection or a render failure. Detail holds only text taken from the template
// source or the schema (an identifier, a parse message); it never holds a rendered value.
type Error struct {
	Code   Code
	Line   int
	Detail string
	render bool
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("msgtemplate: ")
	b.WriteString(string(e.Code))
	if e.Line > 0 {
		b.WriteString(" at line ")
		b.WriteString(strconv.Itoa(e.Line))
	}
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	return b.String()
}

// Unwrap lets callers classify an error with errors.Is(err, ErrInvalidTemplate) or ErrRender.
func (e *Error) Unwrap() error {
	if e.render {
		return ErrRender
	}
	return ErrInvalidTemplate
}

func invalid(code Code, line int, detail string) *Error {
	return &Error{Code: code, Line: line, Detail: detail}
}

func renderError(code Code) *Error {
	return &Error{Code: code, render: true}
}

// lineOf returns the 1-based line of a byte offset in source.
func lineOf(source string, offset int) int {
	if offset < 0 || offset > len(source) {
		return 0
	}
	return 1 + strings.Count(source[:offset], "\n")
}

package msgtemplate

import (
	"errors"
	"testing"
)

func TestErrorReportsLine(t *testing.T) {
	_, err := Compile("test", "ok\n\n{{.secret}}", testSchema())
	var tmplErr *Error
	if !errors.As(err, &tmplErr) || tmplErr.Line != 3 || tmplErr.Detail != "secret" {
		t.Fatalf("err = %#v", err)
	}
}

func TestErrorFormatAndClassification(t *testing.T) {
	compileErr := invalid(CodeUnknownVariable, 2, "secret_name")
	if got := compileErr.Error(); got != "msgtemplate: unknown_variable at line 2: secret_name" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(compileErr, ErrInvalidTemplate) || errors.Is(compileErr, ErrRender) {
		t.Fatal("compile error misclassified")
	}
	renderErr := renderError(CodeInvalidArgument)
	if got := renderErr.Error(); got != "msgtemplate: invalid_argument" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(renderErr, ErrRender) || errors.Is(renderErr, ErrInvalidTemplate) {
		t.Fatal("render error misclassified")
	}
}

func TestLineOf(t *testing.T) {
	source := "a\nb\nc"
	for offset, want := range map[int]int{0: 1, 2: 2, 4: 3, 5: 3, -1: 0, 6: 0} {
		if got := lineOf(source, offset); got != want {
			t.Fatalf("lineOf(%d) = %d, want %d", offset, got, want)
		}
	}
}

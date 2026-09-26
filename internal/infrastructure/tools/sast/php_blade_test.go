package sast

import (
	"strings"
	"testing"
)

// A Blade template's extension is .php and it carries no <?php tag, so tagless mode read the whole file
// as executable PHP: every JavaScript template literal in a <script> block became a PHP backtick shell
// execution, reported CRITICAL. The JavaScript must be masked out of the code view.
func TestBladeMasksScriptBlockJavaScript(t *testing.T) {
	lines := []string{
		`<div class="panel">`,
		`<script>`,
		"    axios.post(`/i/admin/api/show/${id}/reject`, {}).catch(error => {",
		"        console.error(`Error fetching data for ID ${id}:`, error);",
		`    });`,
		`</script>`,
	}
	views := phpLineViews(".php", "resources/views/admin/index.blade.php", lines)
	for i, v := range views {
		if strings.Contains(v.code, "`") {
			t.Errorf("line %d: a JavaScript template literal survived into the PHP code view: %q", i+1, v.code)
		}
		if strings.Contains(v.code, "axios") || strings.Contains(v.code, "console.error") {
			t.Errorf("line %d: JavaScript survived into the PHP code view: %q", i+1, v.code)
		}
	}
}

// The PHP a Blade template does contain must still be scanned, or the fix would trade false positives for
// missed findings. @php blocks and {{ }} / {!! !!} expressions are the PHP in a Blade file.
func TestBladeKeepsItsOwnPHP(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"php block", []string{`@php`, `    $out = shell_exec($cmd);`, `@endphp`}, "shell_exec"},
		{"echo expression", []string{`<p>{{ shell_exec($cmd) }}</p>`}, "shell_exec"},
		{"unescaped expression", []string{`<p>{!! shell_exec($cmd) !!}</p>`}, "shell_exec"},
		{"php tag", []string{`<?php $out = shell_exec($cmd); ?>`}, "shell_exec"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			views := phpLineViews(".php", "views/x.blade.php", c.lines)
			joined := ""
			for _, v := range views {
				joined += v.code + "\n"
			}
			if !strings.Contains(joined, c.want) {
				t.Errorf("the PHP in a Blade template must stay scannable; code view = %q", joined)
			}
		})
	}
}

// A Blade comment is never code.
func TestBladeCommentIsNotCode(t *testing.T) {
	lines := []string{`{{-- shell_exec($cmd) --}}`, `{{--`, `  eval($x);`, `--}}`}
	views := phpLineViews(".php", "views/x.blade.php", lines)
	for i, v := range views {
		if strings.Contains(v.code, "shell_exec") || strings.Contains(v.code, "eval") {
			t.Errorf("line %d: a Blade comment must be masked, got %q", i+1, v.code)
		}
	}
}

// A plain .php file is unaffected: tagless mode still reads it as executable PHP.
func TestPlainPHPUnaffectedByBladeHandling(t *testing.T) {
	lines := []string{`$out = shell_exec($cmd);`}
	views := phpLineViews(".php", "app/Service.php", lines)
	if !strings.Contains(views[0].code, "shell_exec") {
		t.Errorf("a plain .php file must stay in tagless PHP mode, got %q", views[0].code)
	}
}

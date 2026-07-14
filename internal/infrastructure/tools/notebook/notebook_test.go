package notebook

import "testing"

func TestParse(t *testing.T) {
	data := []byte(`{
		"metadata":{"kernelspec":{"name":"python3","display_name":"Python 3"},"language_info":{"name":"python"}},
		"cells":[
			{"cell_type":"markdown","source":["# title\n"]},
			{"cell_type":"code","source":["x = 1\n","print(x)"],"execution_count":2,"outputs":[{"output_type":"stream","text":["1\n"]}]}
		]
	}`)
	doc, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !doc.HasKernelspec || doc.KernelLanguage != "python" || len(doc.Cells) != 2 {
		t.Fatalf("unexpected document: %+v", doc)
	}
	cell := doc.Cells[1]
	if cell.Index != 2 || cell.Type != "code" || cell.Source != "x = 1\nprint(x)" || cell.Output != "1\n" || cell.Traceback != "" || cell.ExecutionCount == nil || *cell.ExecutionCount != 2 {
		t.Fatalf("unexpected code cell: %+v", cell)
	}
	if got := Location("notebooks/example.ipynb", cell.Index); got != "notebooks/example.ipynb#cell-2" {
		t.Fatalf("Location() = %q", got)
	}
}

func TestParseStandardV4Metadata(t *testing.T) {
	doc, err := Parse([]byte(`{"metadata":{"kernelspec":{"name":"python3","display_name":"Python 3"},"language_info":{"name":"python"}},"cells":[]}`))
	if err != nil || !doc.HasKernelspec || doc.KernelLanguage != "python" {
		t.Fatalf("standard v4 metadata = %+v, %v", doc, err)
	}
}

func TestParseSeparatesTracebackText(t *testing.T) {
	doc, err := Parse([]byte(`{"cells":[{"cell_type":"code","outputs":[{"output_type":"error","traceback":["Traceback /home/alice/private.py"]},{"output_type":"stream","text":"saved /home/bob/data.csv"}]}]}`))
	if err != nil || len(doc.Cells) != 1 || doc.Cells[0].Traceback != "Traceback /home/alice/private.py" {
		t.Fatalf("traceback text = %+v, %v", doc, err)
	}
}

func TestParseMalformed(t *testing.T) {
	if _, err := Parse([]byte(`{"cells":`)); err == nil {
		t.Fatal("Parse accepted malformed JSON")
	}
}

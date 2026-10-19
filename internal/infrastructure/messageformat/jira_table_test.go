package messageformat

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJiraAssetTablesKeepHostileCellsAsText(t *testing.T) {
	cell := "[~admin]|!image!{macro}\nnext"
	headers := []string{"Tài sản", "Trạng thái"}
	rows := [][]string{{cell, "Đã xác nhận"}}
	adf, err := JiraADFWithTable("Report", nil, headers, rows)
	if err != nil {
		t.Fatal(err)
	}
	content := adf["content"].([]any)
	table := content[len(content)-1].(map[string]any)
	if table["type"] != "table" {
		t.Fatalf("not an ADF table: %+v", table)
	}
	tableRows := table["content"].([]any)
	cells := tableRows[1].(map[string]any)["content"].([]any)
	text := cells[0].(map[string]any)["content"].([]any)[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if text["text"] != "[~admin]|!image!{macro} next" || text["marks"] != nil {
		t.Fatalf("cell gained active syntax: %+v", text)
	}
	raw, _ := json.Marshal(adf)
	if strings.Contains(string(raw), `"type":"mention"`) {
		t.Fatal("mention node introduced")
	}
	wiki, err := JiraWikiWithTable("Report", nil, headers, rows)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wiki, "||Tài sản||Trạng thái||") || !strings.Contains(wiki, `\[\~admin\]\|\!image\!\{macro\} next`) {
		t.Fatalf("unsafe wiki table: %s", wiki)
	}
}

func TestJiraAssetTableBoundsAndShape(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []string
		rows    [][]string
	}{
		{"empty", nil, nil},
		{"mismatched", []string{"Asset", "State"}, [][]string{{"one"}}},
		{"too many rows", []string{"Asset"}, make([][]string, 101)},
		{"cell overflow", []string{"Asset"}, [][]string{{strings.Repeat("x", 1025)}}},
		{"invalid XML-independent UTF8", []string{"Asset"}, [][]string{{string([]byte{0xff})}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := JiraADFWithTable("Report", nil, tc.headers, tc.rows); err == nil {
				t.Fatal("ADF accepted invalid table")
			}
			if _, err := JiraWikiWithTable("Report", nil, tc.headers, tc.rows); err == nil {
				t.Fatal("wiki accepted invalid table")
			}
		})
	}
}

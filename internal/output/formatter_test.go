package output

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONTableIsOneObjectPerRow(t *testing.T) {
	var buf bytes.Buffer
	f := NewFormatter("json")
	f.SetWriter(&buf)

	f.PrintTable([]string{"ID", "Severity"}, [][]string{{"CVE-1", "high"}, {"CVE-2", "low"}})

	var got []map[string]string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	want := []map[string]string{{"ID": "CVE-1", "Severity": "high"}, {"ID": "CVE-2", "Severity": "low"}}
	if len(got) != 2 || got[0]["ID"] != want[0]["ID"] || got[1]["Severity"] != want[1]["Severity"] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

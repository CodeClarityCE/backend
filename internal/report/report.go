// Package report turns an analysis's findings into the CLI's output formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"codeclarity.io/internal/api"
)

// Report is what results prints: the analysis and every finding it has.
type Report struct {
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id"`
	AnalysisID     string    `json:"analysis_id"`
	Status         string    `json:"status"`
	Findings       []Finding `json:"findings"`
	// SBOM is read only for the formats that write it (NeedsSBOM).
	SBOM *SBOM `json:"-"`
}

// Finding is one vulnerability and the dependencies it affects.
type Finding struct {
	ID string `json:"id"`
	// Severity is critical, high, medium, low or none.
	Severity    string     `json:"severity"`
	Score       float64    `json:"score"`
	Description string     `json:"description"`
	Affected    []Affected `json:"affected"`
}

// Affected is one dependency at one version.
type Affected struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// New builds a report from the API's findings, keeping their order.
func New(org, project string, analysis api.Analysis, findings []api.Finding) Report {
	r := Report{OrganizationID: org, ProjectID: project, AnalysisID: analysis.ID, Status: analysis.Status, Findings: []Finding{}}
	for _, f := range findings {
		out := Finding{
			ID:          f.Vulnerability,
			Severity:    strings.ToLower(f.Severity.Class),
			Score:       f.Severity.Score,
			Description: f.Description,
			Affected:    []Affected{},
		}
		if out.Severity == "" {
			out.Severity = "none"
		}
		for _, a := range f.Affected {
			out.Affected = append(out.Affected, Affected{Package: a.Dependency, Version: a.Version})
		}
		r.Findings = append(r.Findings, out)
	}
	return r
}

// Severities lists the severity classes, highest first.
var Severities = []string{"critical", "high", "medium", "low", "none"}

func rank(severity string) int {
	for i, s := range Severities {
		if s == severity {
			return i
		}
	}
	return len(Severities)
}

// CheckSeverity fails for a name that is not a severity class.
func CheckSeverity(severity string) error {
	if rank(severity) == len(Severities) {
		return fmt.Errorf("unknown severity %q: use one of %s", severity, strings.Join(Severities, ", "))
	}
	return nil
}

// AtOrAbove counts the findings at or above a severity class.
func (r Report) AtOrAbove(severity string) int {
	n := 0
	for _, f := range r.Findings {
		if rank(f.Severity) <= rank(severity) {
			n++
		}
	}
	return n
}

// Options are what a format needs beyond the report.
type Options struct {
	// Manifest is the file SARIF results point at, relative to the repository root.
	Manifest string
	// ToolVersion is the CLI version SARIF names.
	ToolVersion string
}

// Renderer writes a report in one format.
type Renderer func(w io.Writer, r Report, o Options) error

// renderers holds every format results can write, by name.
var renderers = map[string]Renderer{
	"json":  writeJSON,
	"sarif": writeSARIF,
}

// Formats lists the format names, sorted.
func Formats() []string {
	names := make([]string, 0, len(renderers))
	for name := range renderers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Check fails for a format no renderer writes.
func Check(format string) error {
	if _, ok := renderers[format]; !ok {
		return fmt.Errorf("unknown format %q: use one of %s", format, strings.Join(Formats(), ", "))
	}
	return nil
}

// Write writes the report in the named format.
func Write(format string, w io.Writer, r Report, o Options) error {
	if err := Check(format); err != nil {
		return err
	}
	return renderers[format](w, r, o)
}

func writeJSON(w io.Writer, r Report, _ Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

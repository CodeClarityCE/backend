package cmd

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func finding(id, class string, score float64, deps ...string) map[string]any {
	var affected []map[string]any
	for i := 0; i+1 < len(deps); i += 2 {
		affected = append(affected, map[string]any{"AffectedDependency": deps[i], "AffectedVersion": deps[i+1]})
	}
	return map[string]any{
		"Id": id, "Vulnerability": id, "Description": id + " description", "Affected": affected,
		"Severity": map[string]any{"Severity": score, "SeverityClass": class, "SeverityType": "CVSS_V31"},
	}
}

func TestResultsPrintsEveryFindingOfTheLastAnalysisAsJSON(t *testing.T) {
	api := newFakeAPI(t)
	api.findings = []map[string]any{
		finding("CVE-2024-0001", "CRITICAL", 9.8, "lodash", "4.17.20"),
		finding("GHSA-aaaa-bbbb-cccc", "HIGH", 7.5, "ms", "0.7.1", "ms", "0.7.0"),
		finding("CVE-2024-0003", "MEDIUM", 5.0, "axios", "0.21.1"),
		finding("CVE-2024-0004", "LOW", 2.0, "debug", "2.6.8"),
		finding("CVE-2024-0005", "NONE", 0, "qs", "6.5.1"),
	}
	loggedIn(t, api, goodToken)
	run(t, "analyze", project(t), "--analyzer", "Default Analyzer")

	got := run(t, "results", "--format", "json")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
	var report struct {
		OrganizationID string `json:"organization_id"`
		ProjectID      string `json:"project_id"`
		AnalysisID     string `json:"analysis_id"`
		Status         string `json:"status"`
		Findings       []struct {
			ID       string  `json:"id"`
			Severity string  `json:"severity"`
			Score    float64 `json:"score"`
			Affected []struct {
				Package string `json:"package"`
				Version string `json:"version"`
			} `json:"affected"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &report); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, got.stdout)
	}
	if report.OrganizationID != fakeOrg || report.ProjectID != "project-1" || report.AnalysisID != "analysis-1" || report.Status != "completed" {
		t.Fatalf("report %+v", report)
	}
	var severities []string
	for _, f := range report.Findings {
		severities = append(severities, f.ID+":"+f.Severity)
	}
	want := []string{"CVE-2024-0001:critical", "GHSA-aaaa-bbbb-cccc:high", "CVE-2024-0003:medium", "CVE-2024-0004:low", "CVE-2024-0005:none"}
	if !reflect.DeepEqual(severities, want) {
		t.Fatalf("findings %v, want %v", severities, want)
	}
	if ms := report.Findings[1]; ms.Score != 7.5 || len(ms.Affected) != 2 || ms.Affected[1].Package != "ms" || ms.Affected[1].Version != "0.7.0" {
		t.Fatalf("ms finding %+v", ms)
	}
}

func TestResultsOfANamedAnalysisWithAReadToken(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1")

	if got.code != 0 || !strings.Contains(got.stdout, `"findings": []`) {
		t.Fatalf("got %+v", got)
	}
}

func TestResultsRefuseAnAnalysisThatHasNotEnded(t *testing.T) {
	api := newFakeAPI(t)
	api.statuses = []string{"started"}
	loggedIn(t, api, goodToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1")

	if got.code == 0 || !strings.Contains(got.stderr, "analysis analysis-1 is started") {
		t.Fatalf("got %+v", got)
	}
	if api.count("GET", "/projects/project-1/analysis/analysis-1/vulnerabilities") != 0 {
		t.Fatal("read findings of an unfinished analysis")
	}
}

func TestResultsNameTheFormatsTheyWrite(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "xml")

	if got.code == 0 || !strings.Contains(got.stderr, "json") {
		t.Fatalf("got %+v", got)
	}
}

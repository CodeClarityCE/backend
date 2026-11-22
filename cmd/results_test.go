package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestResultsFailOnASeverityAtOrAboveIt(t *testing.T) {
	api := newFakeAPI(t)
	api.findings = []map[string]any{
		finding("CVE-2024-0003", "MEDIUM", 5.0, "axios", "0.21.1"),
		finding("CVE-2024-0004", "LOW", 2.0, "debug", "2.6.8"),
	}
	loggedIn(t, api, goodToken)
	named := []string{"results", "--project", "project-1", "--analysis", "analysis-1"}

	for severity, want := range map[string]int{"critical": 0, "high": 0, "medium": 3, "low": 3, "none": 3} {
		got := run(t, append(named, "--fail-on", severity)...)
		if got.code != want {
			t.Errorf("--fail-on %s: exit %d, want %d (%+v)", severity, got.code, want, got)
		}
		// The findings are printed either way, so the pipeline can keep them.
		if !strings.Contains(got.stdout, "CVE-2024-0003") {
			t.Errorf("--fail-on %s: no findings printed", severity)
		}
		if want != 0 && !strings.Contains(got.stderr, "1 finding at or above "+severity) && !strings.Contains(got.stderr, "2 findings at or above "+severity) {
			t.Errorf("--fail-on %s: stderr %q", severity, got.stderr)
		}
	}
}

func TestResultsWithoutFailOnSucceedWithFindings(t *testing.T) {
	api := newFakeAPI(t)
	api.findings = []map[string]any{finding("CVE-2024-0001", "CRITICAL", 9.8, "lodash", "4.17.20")}
	loggedIn(t, api, goodToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestResultsRefuseAnUnknownFailOnSeverityBeforeAnyRequest(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)
	before := len(api.requests)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--fail-on", "severe")

	if got.code != 1 || !strings.Contains(got.stderr, "critical, high, medium, low, none") {
		t.Fatalf("got %+v", got)
	}
	if len(api.requests) != before {
		t.Fatalf("sent %v", api.requests[before:])
	}
}

// sarifURIs returns the $schema and each result's artifact uri of a SARIF log.
func sarifURIs(t *testing.T, doc string) (string, []string) {
	t.Helper()
	var log struct {
		Schema string `json:"$schema"`
		Runs   []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(doc), &log); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, doc)
	}
	var uris []string
	for _, r := range log.Runs[0].Results {
		uris = append(uris, r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	return log.Schema, uris
}

func TestResultsWriteSARIFPointingAtTheCheckoutsLockfile(t *testing.T) {
	api := newFakeAPI(t)
	api.findings = []map[string]any{finding("GHSA-aaaa-bbbb-cccc", "HIGH", 7.5, "ms", "0.7.1")}
	loggedIn(t, api, goodToken)
	checkout := t.TempDir()
	for _, name := range []string{"package.json", "package-lock.json"} {
		if err := os.WriteFile(filepath.Join(checkout, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(checkout)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "sarif", "--fail-on", "high")

	if got.code != 3 {
		t.Fatalf("got %+v", got)
	}
	schema, uris := sarifURIs(t, got.stdout)
	if schema != "https://json.schemastore.org/sarif-2.1.0.json" || !reflect.DeepEqual(uris, []string{"package-lock.json"}) {
		t.Fatalf("schema %q, uris %v", schema, uris)
	}
}

func TestResultsSARIFTakesTheManifestToPointAt(t *testing.T) {
	api := newFakeAPI(t)
	api.findings = []map[string]any{finding("GHSA-aaaa-bbbb-cccc", "HIGH", 7.5, "ms", "0.7.1")}
	loggedIn(t, api, goodToken)
	t.Chdir(t.TempDir())

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "sarif", "--manifest", "web/composer.lock")

	if _, uris := sarifURIs(t, got.stdout); got.code != 0 || !reflect.DeepEqual(uris, []string{"web/composer.lock"}) {
		t.Fatalf("got %+v", got)
	}
}

func TestResultsSARIFWithoutAManifestAsksForOneBeforeAnyRequest(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)
	t.Chdir(t.TempDir())
	before := len(api.requests)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "sarif")

	if got.code != 1 || !strings.Contains(got.stderr, "--manifest") || len(api.requests) != before {
		t.Fatalf("got %+v", got)
	}
}

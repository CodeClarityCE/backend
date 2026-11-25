package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// analysedWithReadToken runs analyze with a full token, then logs in again with a read token,
// as a developer reading a pipeline's results would.
func analysedWithReadToken(t *testing.T, api *fakeAPI) {
	t.Helper()
	loggedIn(t, api, goodToken)
	if got := run(t, "analyze", project(t), "--analyzer", "Default Analyzer"); got.code != 0 {
		t.Fatalf("analyze: %+v", got)
	}
	if got := run(t, "login", "--url", api.url(), "--org", fakeOrg, "--token", readToken); got.code != 0 {
		t.Fatalf("login: %+v", got)
	}
}

func decode[T any](t *testing.T, got result) T {
	t.Helper()
	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
	var v T
	if err := json.Unmarshal([]byte(got.stdout), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, got.stdout)
	}
	return v
}

func TestAnalysesListsTheLastProjectsAnalysesWithoutTheirConfig(t *testing.T) {
	api := newFakeAPI(t)
	analysedWithReadToken(t, api)

	analyses := decode[[]map[string]any](t, run(t, "analyses"))

	if len(analyses) != 2 || analyses[0]["id"] != "analysis-1" || analyses[1]["failure_reason"] != "clone failed" {
		t.Fatalf("got %v", analyses)
	}
	if _, ok := analyses[0]["config"]; ok {
		t.Errorf("the config leaked into the list: %v", analyses[0])
	}
}

func TestAnalysesNeedsAProjectWithoutAPreviousAnalyze(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)

	got := run(t, "analyses")

	if got.code != 1 || !strings.Contains(got.stderr, "pass --project") {
		t.Fatalf("got %+v", got)
	}
}

func TestLicensesReadsEveryPage(t *testing.T) {
	api := newFakeAPI(t)
	api.licenses = []map[string]any{
		{"id": "MIT", "deps_using_license": []string{"lodash@4.17.20"}},
		{"id": "ISC", "deps_using_license": []string{"once@1.4.0"}},
		{"id": "GPL-3.0", "deps_using_license": []string{"gpl-thing@1.0.0"}, "license_compliance_violation": true},
	}
	analysedWithReadToken(t, api)

	licenses := decode[[]map[string]any](t, run(t, "licenses"))

	if len(licenses) != 3 || licenses[2]["license_compliance_violation"] != true {
		t.Fatalf("got %v", licenses)
	}
}

func TestLicensesOfAnAnalysisThatHasNotEndedSaySo(t *testing.T) {
	api := newFakeAPI(t)
	analysedWithReadToken(t, api)
	api.statuses = []string{"started"}
	api.analysisPolls = 0

	got := run(t, "licenses")

	if got.code != 1 || !strings.Contains(got.stderr, "is started, so it has no results yet") {
		t.Fatalf("got %+v", got)
	}
}

func TestExplainPrintsTheDependencyAndThePathToIt(t *testing.T) {
	api := newFakeAPI(t)
	analysedWithReadToken(t, api)

	out := decode[struct {
		Dependency map[string]any   `json:"dependency"`
		Graph      []map[string]any `json:"graph"`
	}](t, run(t, "explain", "lodash@4.17.20"))

	if out.Dependency["transitive"] != true || len(out.Graph) != 2 || out.Graph[0]["id"] != "express@4.18.0" {
		t.Fatalf("got %+v", out)
	}
}

func TestExplainWantsNameAtVersion(t *testing.T) {
	api := newFakeAPI(t)
	analysedWithReadToken(t, api)
	for _, arg := range []string{"lodash", "lodash@", "@4.17.20"} {
		got := run(t, "explain", arg)
		if got.code != 1 || !strings.Contains(got.stderr, "name@version") {
			t.Errorf("%s: got %+v", arg, got)
		}
	}
}

func TestExplainAnUnknownDependencySaysSo(t *testing.T) {
	api := newFakeAPI(t)
	analysedWithReadToken(t, api)

	got := run(t, "explain", "left-pad@1.0.0")

	if got.code != 1 || !strings.Contains(got.stderr, "Dependency not found (HTTP 404") {
		t.Fatalf("got %+v", got)
	}
}

func TestFixNextPassesTheLimit(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)

	entries := decode[[]map[string]any](t, run(t, "fix-next", "--limit", "5"))

	if len(entries) != 1 || entries[0]["target_version"] != "4.17.21" {
		t.Fatalf("got %v", entries)
	}
	if api.fixNextQuery != "limit=5" {
		t.Errorf("query: %q", api.fixNextQuery)
	}
}

func TestFixNextRefusesALimitTheAPIRefuses(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)
	for _, limit := range []string{"0", "51"} {
		got := run(t, "fix-next", "--limit", limit)
		if got.code != 1 || !strings.Contains(got.stderr, "between 1 and 50") {
			t.Errorf("%s: got %+v", limit, got)
		}
	}
	if n := api.count("GET", "/remediations/fix-next"); n != 0 {
		t.Errorf("called the API %d times", n)
	}
}

func TestVulnDescribesAVulnerabilityAndTheProjectsItAffects(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)

	page := decode[map[string]any](t, run(t, "vuln", "CVE-2021-23337"))

	if page["severity_class"] != "HIGH" || len(page["projects"].([]any)) != 1 {
		t.Fatalf("got %v", page)
	}
}

func TestVulnUnknownSaysSo(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)

	got := run(t, "vuln", "CVE-1999-0001")

	if got.code != 1 || !strings.Contains(got.stderr, "reading vulnerability CVE-1999-0001") {
		t.Fatalf("got %+v", got)
	}
}

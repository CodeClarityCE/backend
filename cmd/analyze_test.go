package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fastPolling makes waiting for an analysis take milliseconds.
func fastPolling(t *testing.T) {
	t.Helper()
	pollFirst, pollMax = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { pollFirst, pollMax = defaultPollFirst, defaultPollMax })
}

// loggedIn logs the CLI in to api with token and makes waiting fast.
func loggedIn(t *testing.T, api *fakeAPI, token string) {
	t.Helper()
	isolate(t)
	fastPolling(t)
	if got := run(t, "login", "--url", api.url(), "--org", fakeOrg, "--token", token); got.code != 0 {
		t.Fatalf("login: %+v", got)
	}
}

// project writes a small npm project and returns its directory.
func project(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "shop-front")
	files := map[string]string{
		"package.json":                   `{"name":"shop-front"}`,
		"package-lock.json":              `{"lockfileVersion":3}`,
		"src/index.js":                   "console.log(1)",
		".git/config":                    "[core]",
		"node_modules/left-pad/index.js": "module.exports = 1",
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestAnalyzeUploadsTheDirectoryAndWaitsForTheAnalysis(t *testing.T) {
	api := newFakeAPI(t)
	api.statuses = []string{"requested", "started", "started", "completed"}
	loggedIn(t, api, goodToken)

	// It waits by default.
	got := run(t, "analyze", project(t), "--analyzer", "Default Analyzer")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
	var printed map[string]string
	if err := json.Unmarshal([]byte(got.stdout), &printed); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, got.stdout)
	}
	want := map[string]string{"organization_id": fakeOrg, "project_id": "project-1", "analysis_id": "analysis-1", "status": "completed"}
	if !reflect.DeepEqual(printed, want) {
		t.Fatalf("printed %v, want %v", printed, want)
	}
	if api.projectName != "shop-front" {
		t.Fatalf("project name %q", api.projectName)
	}
	files := api.uploadedFiles()
	var names []string
	for name := range files {
		names = append(names, name)
	}
	if len(files) != 3 || files["package.json"] != `{"name":"shop-front"}` || files["src/index.js"] == "" || files["package-lock.json"] == "" {
		t.Fatalf("uploaded %v", names)
	}
	if api.count("GET", "/projects/project-1/analyses/analysis-1") != 4 {
		t.Fatalf("polled %d times", api.count("GET", "/projects/project-1/analyses/analysis-1"))
	}
}

func TestAnalyzeConfiguresThePluginsAsTheWebAppDoes(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", project(t), "--analyzer", "Default Analyzer", "--no-wait")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
	want := map[string]any{
		"analyzer_id": "analyzer-default",
		"branch":      "main",
		"config": map[string]any{
			"js-sbom":        map[string]any{"branch": "main", "project": fakeOrg + "/projects/project-1/main"},
			"vuln-finder":    map[string]any{"vulnerabilityPolicy": []any{}},
			"license-finder": map[string]any{"licensePolicy": []any{}},
		},
	}
	if !reflect.DeepEqual(api.startBody, want) {
		t.Fatalf("started with %v, want %v", api.startBody, want)
	}
	// With --no-wait it does not poll.
	if n := api.count("GET", "/projects/project-1/analyses/analysis-1"); n != 0 {
		t.Fatalf("polled %d times", n)
	}
}

func TestAnalyzeRefusesWaitAndNoWaitTogether(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", project(t), "--wait", "--no-wait")

	if got.code == 0 || api.startBody != nil {
		t.Fatalf("got %+v, started with %v", got, api.startBody)
	}
}

func TestAnalyzeTakesAnAnalyzerIDAndAProjectName(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", project(t), "--analyzer", "analyzer-php", "--name", "ci-shop")

	if got.code != 0 || api.startBody["analyzer_id"] != "analyzer-php" || api.projectName != "ci-shop" {
		t.Fatalf("got %+v, started %v, project %q", got, api.startBody, api.projectName)
	}
}

func TestAnalyzeNamesTheAnalyzersWhenNoneMatches(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", project(t), "--analyzer", "Nope")

	if got.code == 0 || !strings.Contains(got.stderr, `"Default Analyzer"`) {
		t.Fatalf("got %+v", got)
	}
	if api.count("POST", "/projects") != 0 {
		t.Fatal("created a project for an unknown analyzer")
	}
}

func TestAnalyzeFailsWhenTheAnalysisFails(t *testing.T) {
	api := newFakeAPI(t)
	api.statuses = []string{"started", "failed"}
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", project(t), "--analyzer", "Default Analyzer", "--wait")

	if got.code == 0 || !strings.Contains(got.stderr, "analysis analysis-1 failed") {
		t.Fatalf("got %+v", got)
	}
}

func TestAnalyzeStopsWaitingAtTheTimeout(t *testing.T) {
	api := newFakeAPI(t)
	api.statuses = []string{"started"}
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", project(t), "--analyzer", "Default Analyzer", "--wait", "--timeout", "50ms")

	if got.code == 0 || !strings.Contains(got.stderr, "still started after 50ms") {
		t.Fatalf("got %+v", got)
	}
}

func TestAnalyzeWithAReadTokenIsRefused(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)

	got := run(t, "analyze", project(t), "--analyzer", "Default Analyzer")

	if got.code == 0 || !strings.Contains(got.stderr, "analyze scope") {
		t.Fatalf("got %+v", got)
	}
}

func TestAnalyzeWorksFromTheEnvironmentAlone(t *testing.T) {
	api := newFakeAPI(t)
	isolate(t)
	fastPolling(t)
	t.Setenv("CODECLARITY_URL", api.url())
	t.Setenv("CODECLARITY_ORG", fakeOrg)
	t.Setenv("CODECLARITY_TOKEN", goodToken)

	got := run(t, "analyze", project(t), "--analyzer", "Default Analyzer")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestAnalyzeDoesNotFollowLinksOutOfTheDirectory(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)
	dir := project(t)
	secret := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(secret, []byte("private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(secret), filepath.Join(dir, "outside")); err != nil {
		t.Fatal(err)
	}

	if got := run(t, "analyze", dir, "--analyzer", "Default Analyzer"); got.code != 0 {
		t.Fatalf("got %+v", got)
	}

	for name, content := range api.uploadedFiles() {
		if strings.Contains(content, "private key") {
			t.Fatalf("uploaded %s from outside the directory", name)
		}
	}
}

func TestAnalyzeALinkedProjectOnItsDefaultBranchWithoutUploading(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", "--project", linkedProject, "--analyzer", "Default Analyzer", "--wait")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
	var printed map[string]string
	_ = json.Unmarshal([]byte(got.stdout), &printed)
	if printed["project_id"] != linkedProject || printed["analysis_id"] != "analysis-1" || printed["status"] != "completed" {
		t.Fatalf("printed %v", printed)
	}
	if api.count("POST", "/projects") != 0 || len(api.uploaded) != 0 {
		t.Fatal("a linked project was uploaded")
	}
	want := map[string]any{
		"analyzer_id": "analyzer-default",
		"branch":      "develop",
		"config": map[string]any{
			"js-sbom":        map[string]any{"branch": "develop", "project": fakeOrg + "/projects/" + linkedProject + "/develop"},
			"vuln-finder":    map[string]any{"vulnerabilityPolicy": []any{}},
			"license-finder": map[string]any{"licensePolicy": []any{}},
		},
	}
	if !reflect.DeepEqual(api.startBody, want) {
		t.Fatalf("started with %v, want %v", api.startBody, want)
	}
	// results then reads this analysis.
	if got := run(t, "results"); got.code != 0 || !strings.Contains(got.stdout, `"project_id": "`+linkedProject+`"`) {
		t.Fatalf("results: %+v", got)
	}
}

func TestAnalyzeALinkedProjectOnANamedBranch(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", "--project", linkedProject, "--branch", "release/2.x")

	if got.code != 0 || api.startBody["branch"] != "release/2.x" {
		t.Fatalf("got %+v, started with %v", got, api.startBody)
	}
}

func TestAnalyzeAnUploadedProjectAgainUsesItsUpload(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", "--project", "project-1")

	if got.code != 0 || api.startBody["branch"] != "main" || len(api.uploaded) != 0 {
		t.Fatalf("got %+v, started with %v", got, api.startBody)
	}
}

func TestAnalyzeTakesADirectoryOrAProjectNotBoth(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)
	before := len(api.requests)

	for _, args := range [][]string{{"analyze"}, {"analyze", project(t), "--project", linkedProject}, {"analyze", project(t), "--branch", "main"}} {
		if got := run(t, args...); got.code != 1 {
			t.Errorf("%v: got %+v", args, got)
		}
	}
	if len(api.requests) != before {
		t.Fatalf("sent %v", api.requests[before:])
	}
}

func TestAnalyzeAnUnknownProjectSaysSo(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, goodToken)

	got := run(t, "analyze", "--project", "no-such-project")

	if got.code != 1 || !strings.Contains(got.stderr, "no-such-project") || api.count("POST", "/projects/no-such-project/analyses") != 0 {
		t.Fatalf("got %+v", got)
	}
}

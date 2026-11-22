package cmd

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func dependency(name, version, purl, license string) map[string]any {
	return map[string]any{"name": name, "version": version, "purl": purl, "license": license, "prod": true, "is_direct_count": 1}
}

// cycloneDX is the part of a CycloneDX BOM the tests read.
type cycloneDX struct {
	BOMFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"components"`
		} `json:"tools"`
		Component struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Type     string `json:"type"`
		BOMRef   string `json:"bom-ref"`
		Name     string `json:"name"`
		Version  string `json:"version"`
		PURL     string `json:"purl"`
		Licenses []struct {
			Expression string `json:"expression"`
			License    struct {
				Name string `json:"name"`
			} `json:"license"`
		} `json:"licenses"`
	} `json:"components"`
}

func TestResultsWriteACycloneDXBOMOfEveryWorkspace(t *testing.T) {
	api := newFakeAPI(t)
	api.sbom = map[string][]map[string]any{
		".": {dependency("ms", "0.7.1", "pkg:npm/ms@0.7.1", "MIT")},
		"api": {
			dependency("@nestjs/core", "11.0.0", "pkg:npm/%40nestjs/core@11.0.0", "MIT"),
			dependency("ms", "0.7.1", "pkg:npm/ms@0.7.1", "MIT"),
			dependency("dual", "1.0.0", "pkg:npm/dual@1.0.0", "(MIT OR Apache-2.0)"),
		},
		"frontend": {dependency("odd", "2.0.0", "pkg:npm/odd@2.0.0", "SEE LICENSE IN LICENSE.md")},
	}
	setVersion(t, "9.9.9-test")
	loggedIn(t, api, readToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "cyclonedx",
		"--component-name", "codeclarity", "--component-version", "v1.2.3")

	if got.code != 0 {
		t.Fatalf("got %+v", got)
	}
	var bom cycloneDX
	if err := json.Unmarshal([]byte(got.stdout), &bom); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, got.stdout)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || bom.Version != 1 {
		t.Fatalf("header %+v", bom)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(bom.SerialNumber) {
		t.Fatalf("serial number %q", bom.SerialNumber)
	}
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`).MatchString(bom.Metadata.Timestamp) {
		t.Fatalf("timestamp %q", bom.Metadata.Timestamp)
	}
	if m := bom.Metadata; m.Component.Type != "application" || m.Component.Name != "codeclarity" || m.Component.Version != "v1.2.3" ||
		len(m.Tools.Components) != 1 || m.Tools.Components[0].Name != "codeclarity" || m.Tools.Components[0].Version != "9.9.9-test" {
		t.Fatalf("metadata %+v", m)
	}
	// One component per package URL across the workspaces, sorted by it.
	var purls []string
	for _, c := range bom.Components {
		if c.Type != "library" || c.BOMRef != c.PURL {
			t.Fatalf("component %+v", c)
		}
		purls = append(purls, c.PURL)
	}
	want := []string{"pkg:npm/%40nestjs/core@11.0.0", "pkg:npm/dual@1.0.0", "pkg:npm/ms@0.7.1", "pkg:npm/odd@2.0.0"}
	if !reflect.DeepEqual(purls, want) {
		t.Fatalf("components %v, want %v", purls, want)
	}
	if c := bom.Components[0]; c.Name != "@nestjs/core" || c.Version != "11.0.0" || len(c.Licenses) != 1 || c.Licenses[0].Expression != "MIT" {
		t.Fatalf("nestjs %+v", c)
	}
	if l := bom.Components[1].Licenses; len(l) != 1 || l[0].Expression != "(MIT OR Apache-2.0)" {
		t.Fatalf("dual licenses %+v", l)
	}
	if l := bom.Components[3].Licenses; len(l) != 1 || l[0].Expression != "" || l[0].License.Name != "SEE LICENSE IN LICENSE.md" {
		t.Fatalf("odd licenses %+v", l)
	}
	// The SBOM is paged two at a time, so api needed two pages.
	if n := api.count("GET", "/projects/project-1/analysis/analysis-1/sbom"); n != 4 {
		t.Fatalf("read %d SBOM pages, want 4", n)
	}
}

func TestResultsWriteACycloneDXBOMOfOneWorkspace(t *testing.T) {
	api := newFakeAPI(t)
	api.sbom = map[string][]map[string]any{
		".":   {dependency("ms", "0.7.1", "pkg:npm/ms@0.7.1", "")},
		"api": {dependency("lodash", "4.17.20", "pkg:npm/lodash@4.17.20", "MIT")},
	}
	loggedIn(t, api, readToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "cyclonedx", "--workspace", ".")

	var bom cycloneDX
	if got.code != 0 || json.Unmarshal([]byte(got.stdout), &bom) != nil {
		t.Fatalf("got %+v", got)
	}
	// Without --component-name the BOM is named after the project.
	if bom.Metadata.Component.Name != "project-1" || len(bom.Components) != 1 || bom.Components[0].Name != "ms" || bom.Components[0].Licenses != nil {
		t.Fatalf("bom %+v", bom)
	}
}

func TestResultsFailWhenTheSBOMCannotBeRead(t *testing.T) {
	api := newFakeAPI(t)
	loggedIn(t, api, readToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "cyclonedx")

	if got.code == 0 || got.stdout != "" || !strings.Contains(got.stderr, "reading the SBOM of analysis analysis-1") {
		t.Fatalf("got %+v", got)
	}
}

func TestResultsWriteAnEmptyBOMForAnAnalysisWithNoDependencies(t *testing.T) {
	api := newFakeAPI(t)
	api.sbom = map[string][]map[string]any{".": {}}
	loggedIn(t, api, readToken)

	got := run(t, "results", "--project", "project-1", "--analysis", "analysis-1", "--format", "cyclonedx")

	if got.code != 0 || !strings.Contains(got.stdout, `"components": []`) {
		t.Fatalf("got %+v", got)
	}
}

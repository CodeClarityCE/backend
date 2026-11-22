package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The SARIF 2.1.0 schemas in testdata, pinned by hash: the OASIS standard
// (docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
// and the copy GitHub's code scanning docs point at (json.schemastore.org/sarif-2.1.0.json).
var sarifSchemas = map[string]string{
	"sarif-schema-2.1.0.json":      "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e",
	"schemastore-sarif-2.1.0.json": "c96eb2d311c37b0a38cbd18c52d79a68f778bbd2d831abed7412d9850740f785",
}

func sample() Report {
	return Report{
		OrganizationID: "org-1", ProjectID: "project-1", AnalysisID: "analysis-1", Status: "completed",
		Findings: []Finding{
			{ID: "CVE-2024-0001", Severity: "critical", Score: 9.8, Description: "Prototype pollution in lodash.", Affected: []Affected{{"lodash", "4.17.20"}}},
			{ID: "GHSA-w9mr-4mfr-499f", Severity: "high", Score: 7.5, Description: "ms is vulnerable to ReDoS. " + strings.Repeat("x", 2000), Affected: []Affected{{"ms", "0.7.1"}, {"ms", "0.7.0"}}},
			{ID: "CVE-2024-0003", Severity: "medium", Score: 5, Description: "", Affected: []Affected{{"axios", "0.21.1"}}},
			{ID: "CVE-2024-0004", Severity: "low", Score: 2, Description: "Low.", Affected: []Affected{{"debug", "2.6.8"}}},
			{ID: "CVE-2024-0005", Severity: "none", Score: 0, Description: "None.", Affected: []Affected{{"qs", "6.5.1"}}},
		},
	}
}

func renderSARIF(t *testing.T, r Report, o Options) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Write("sarif", &out, r, o); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestSARIFIsValidAgainstThePinnedSchemas(t *testing.T) {
	for name, report := range map[string]Report{"findings": sample(), "no findings": {Findings: []Finding{}}} {
		doc := renderSARIF(t, report, Options{Manifest: "package-lock.json", ToolVersion: "1.2.3"})
		for path, sum := range sarifSchemas {
			raw, err := fs.ReadFile(os.DirFS("testdata"), path)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != sum {
				t.Fatalf("%s changed: pin its new hash only after checking where it came from", path)
			}
			schema, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			c := jsonschema.NewCompiler()
			if err := c.AddResource("sarif.json", schema); err != nil {
				t.Fatal(err)
			}
			compiled, err := c.Compile("sarif.json")
			if err != nil {
				t.Fatal(err)
			}
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
			if err != nil {
				t.Fatal(err)
			}
			if err := compiled.Validate(instance); err != nil {
				t.Errorf("%s against %s: %v", name, path, err)
			}
		}
	}
}

// sarifLog holds the parts of a SARIF log GitHub code scanning reads.
type sarifLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID               string                `json:"id"`
					ShortDescription struct{ Text string } `json:"shortDescription"`
					FullDescription  struct{ Text string } `json:"fullDescription"`
					Help             struct{ Text string } `json:"help"`
					Properties       struct {
						Tags             []string `json:"tags"`
						SecuritySeverity string   `json:"security-severity"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		AutomationDetails struct {
			ID string `json:"id"`
		} `json:"automationDetails"`
		Results []struct {
			RuleID    string                `json:"ruleId"`
			RuleIndex int                   `json:"ruleIndex"`
			Level     string                `json:"level"`
			Message   struct{ Text string } `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine, StartColumn, EndLine, EndColumn int
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

func TestSARIFHasWhatGitHubCodeScanningRequires(t *testing.T) {
	var log sarifLog
	if err := json.Unmarshal(renderSARIF(t, sample(), Options{Manifest: "web/package-lock.json", ToolVersion: "1.2.3"}), &log); err != nil {
		t.Fatal(err)
	}
	if log.Schema != "https://json.schemastore.org/sarif-2.1.0.json" || log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("log %+v", log)
	}
	run := log.Runs[0]
	driver := run.Tool.Driver
	if driver.Name != "CodeClarity" || driver.Version != "1.2.3" {
		t.Fatalf("driver %+v", driver)
	}
	// One upload per manifest: a second upload for the same manifest replaces the first.
	if run.AutomationDetails.ID != "codeclarity/web/package-lock.json/" {
		t.Fatalf("automation id %q", run.AutomationDetails.ID)
	}

	wantSeverity := map[string]string{"CVE-2024-0001": "9.8", "GHSA-w9mr-4mfr-499f": "7.5", "CVE-2024-0003": "5.0", "CVE-2024-0004": "2.0", "CVE-2024-0005": ""}
	if len(driver.Rules) != len(wantSeverity) {
		t.Fatalf("%d rules", len(driver.Rules))
	}
	for _, rule := range driver.Rules {
		if rule.ShortDescription.Text == "" || rule.FullDescription.Text == "" || rule.Help.Text == "" {
			t.Errorf("rule %s has an empty required text: %+v", rule.ID, rule)
		}
		if len(rule.ShortDescription.Text) > 1024 || len(rule.FullDescription.Text) > 1024 {
			t.Errorf("rule %s has a description over GitHub's 1024 characters", rule.ID)
		}
		if rule.Properties.SecuritySeverity != wantSeverity[rule.ID] {
			t.Errorf("rule %s security-severity %q, want %q", rule.ID, rule.Properties.SecuritySeverity, wantSeverity[rule.ID])
		}
		if len(rule.Properties.Tags) == 0 || rule.Properties.Tags[0] != "security" {
			t.Errorf("rule %s tags %v", rule.ID, rule.Properties.Tags)
		}
	}
	if !strings.Contains(driver.Rules[1].Help.Text, strings.Repeat("x", 2000)) {
		t.Error("help should keep the whole description")
	}

	// One alert per affected dependency.
	wantResults := []string{
		"CVE-2024-0001 error lodash@4.17.20",
		"GHSA-w9mr-4mfr-499f error ms@0.7.1",
		"GHSA-w9mr-4mfr-499f error ms@0.7.0",
		"CVE-2024-0003 warning axios@0.21.1",
		"CVE-2024-0004 note debug@2.6.8",
		"CVE-2024-0005 note qs@6.5.1",
	}
	if len(run.Results) != len(wantResults) {
		t.Fatalf("%d results, want %d", len(run.Results), len(wantResults))
	}
	fingerprints := map[string]bool{}
	for i, res := range run.Results {
		fields := strings.Fields(wantResults[i])
		if res.RuleID != fields[0] || res.Level != fields[1] || !strings.HasPrefix(res.Message.Text, fields[2]+" ") {
			t.Errorf("result %d: %s %s %q, want %s", i, res.RuleID, res.Level, res.Message.Text, wantResults[i])
		}
		if driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %d: ruleIndex %d is not %s", i, res.RuleIndex, res.RuleID)
		}
		if len(res.Locations) != 1 {
			t.Fatalf("result %d: %d locations", i, len(res.Locations))
		}
		loc := res.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != "web/package-lock.json" || loc.ArtifactLocation.URIBaseID != "%SRCROOT%" {
			t.Errorf("result %d: artifact %+v", i, loc.ArtifactLocation)
		}
		if loc.Region.StartLine != 1 || loc.Region.StartColumn != 1 || loc.Region.EndLine != 1 || loc.Region.EndColumn < 1 {
			t.Errorf("result %d: region %+v", i, loc.Region)
		}
		hash := res.PartialFingerprints["primaryLocationLineHash"]
		if hash == "" || fingerprints[hash] {
			t.Errorf("result %d: fingerprint %q is empty or repeated", i, hash)
		}
		fingerprints[hash] = true
	}
}

func TestSARIFFingerprintsStayTheSameAcrossRuns(t *testing.T) {
	var first, second sarifLog
	o := Options{Manifest: "package-lock.json"}
	_ = json.Unmarshal(renderSARIF(t, sample(), o), &first)
	later := sample()
	later.AnalysisID = "analysis-2"
	later.Findings = later.Findings[1:]
	_ = json.Unmarshal(renderSARIF(t, later, o), &second)

	if first.Runs[0].Results[1].PartialFingerprints["primaryLocationLineHash"] != second.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"] {
		t.Fatal("the same finding got a new fingerprint in a later analysis")
	}
}

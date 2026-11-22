package report

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"codeclarity.io/internal/api"
)

// SBOM is what an SBOM format writes: the analysed software and its dependencies.
type SBOM struct {
	// Name and Version name the analysed software; Name defaults to the project id.
	Name    string
	Version string
	// ToolVersion is the CLI's version.
	ToolVersion  string
	Dependencies []api.Dependency
}

// sbomFormats are the formats that write the SBOM instead of the findings.
var sbomFormats = map[string]bool{"cyclonedx": true}

func init() {
	renderers["cyclonedx"] = writeCycloneDX
}

// NeedsSBOM reports whether a format writes the report's SBOM.
func NeedsSBOM(format string) bool { return sbomFormats[format] }

type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string `json:"timestamp"`
	Tools     struct {
		Components []cdxComponent `json:"components"`
	} `json:"tools"`
	Component cdxComponent `json:"component"`
}

type cdxComponent struct {
	Type     string       `json:"type"`
	BOMRef   string       `json:"bom-ref,omitempty"`
	Name     string       `json:"name"`
	Version  string       `json:"version,omitempty"`
	PURL     string       `json:"purl,omitempty"`
	Licenses []cdxLicense `json:"licenses,omitempty"`
}

type cdxLicense struct {
	Expression string          `json:"expression,omitempty"`
	License    *cdxLicenseName `json:"license,omitempty"`
}

type cdxLicenseName struct {
	Name string `json:"name"`
}

// writeCycloneDX writes the SBOM as CycloneDX 1.6 JSON, one component per package URL.
func writeCycloneDX(w io.Writer, r Report) error {
	if r.SBOM == nil {
		return fmt.Errorf("the report has no SBOM")
	}
	serial, err := uuid4()
	if err != nil {
		return err
	}
	bom := cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", SerialNumber: "urn:uuid:" + serial, Version: 1, Components: []cdxComponent{}}
	bom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	bom.Metadata.Tools.Components = []cdxComponent{{Type: "application", Name: "codeclarity", Version: r.SBOM.ToolVersion}}
	bom.Metadata.Component = cdxComponent{Type: "application", Name: r.SBOM.Name, Version: r.SBOM.Version}
	if bom.Metadata.Component.Name == "" {
		bom.Metadata.Component.Name = r.ProjectID
	}

	seen := map[string]bool{}
	for _, d := range r.SBOM.Dependencies {
		if d.PURL == "" || seen[d.PURL] {
			continue
		}
		seen[d.PURL] = true
		bom.Components = append(bom.Components, cdxComponent{
			Type: "library", BOMRef: d.PURL, Name: d.Name, Version: d.Version, PURL: d.PURL, Licenses: cdxLicenses(d.License),
		})
	}
	sort.Slice(bom.Components, func(i, j int) bool { return bom.Components[i].PURL < bom.Components[j].PURL })

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// cdxLicenses writes an SPDX expression as one, and any other text as a license name.
func cdxLicenses(license string) []cdxLicense {
	text := strings.TrimSpace(license)
	switch {
	case text == "":
		return nil
	case isSPDXExpression(text):
		return []cdxLicense{{Expression: text}}
	default:
		return []cdxLicense{{License: &cdxLicenseName{Name: text}}}
	}
}

var spdxID = regexp.MustCompile(`^[A-Za-z0-9.+-]+$`)

// isSPDXExpression reports whether text reads as SPDX ids joined by AND, OR or WITH, as the web app's export checks.
func isSPDXExpression(text string) bool {
	tokens := strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(text))
	depth, wantID := 0, true
	for _, token := range tokens {
		switch token {
		case "(":
			if !wantID {
				return false
			}
			depth++
		case ")":
			depth--
			if wantID || depth < 0 {
				return false
			}
		case "AND", "OR", "WITH":
			if wantID {
				return false
			}
			wantID = true
		default:
			if !wantID || !spdxID.MatchString(token) {
				return false
			}
			wantID = false
		}
	}
	return depth == 0 && !wantID
}

// uuid4 returns a random version 4 UUID.
func uuid4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

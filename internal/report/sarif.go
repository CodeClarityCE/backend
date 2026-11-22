package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// SARIF 2.1.0 as GitHub code scanning reads it:
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

const (
	sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"
	// GitHub keeps 1024 characters of a rule's descriptions.
	maxDescription = 1024
)

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	Help                 sarifText      `json:"help"`
	DefaultConfiguration map[string]any `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []any             `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

// level is the SARIF level of a severity class.
func level(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

// truncate cuts text to at most limit bytes, on a rune boundary.
func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := limit - len("...")
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}

// fingerprint names one finding on one dependency the same way in every analysis.
func fingerprint(id string, a Affected, manifest string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{id, a.Package, a.Version, manifest}, "\x00")))
	return hex.EncodeToString(sum[:16]) + ":1"
}

func packages(f Finding) string {
	var names []string
	seen := map[string]bool{}
	for _, a := range f.Affected {
		if !seen[a.Package] {
			seen[a.Package] = true
			names = append(names, a.Package)
		}
	}
	return strings.Join(names, ", ")
}

func sarifRuleFor(f Finding) sarifRule {
	description := f.Description
	if description == "" {
		description = f.ID
	}
	short := f.ID
	if p := packages(f); p != "" {
		short += " in " + p
	}
	properties := map[string]any{"tags": []string{"security", "dependency", "vulnerability"}, "precision": "high"}
	// GitHub maps 0.1 to 10.0 to low, medium, high and critical; 0 has no severity.
	if f.Score > 0 {
		properties["security-severity"] = fmt.Sprintf("%.1f", min(f.Score, 10))
	}
	return sarifRule{
		ID:                   f.ID,
		Name:                 f.ID,
		ShortDescription:     sarifText{truncate(short, maxDescription)},
		FullDescription:      sarifText{truncate(description, maxDescription)},
		Help:                 sarifText{fmt.Sprintf("%s (severity %s, score %.1f)\n\n%s", f.ID, f.Severity, f.Score, description)},
		DefaultConfiguration: map[string]any{"level": level(f.Severity)},
		Properties:           properties,
	}
}

// writeSARIF writes one result per affected dependency, located at the manifest's first line.
func writeSARIF(w io.Writer, r Report, o Options) error {
	if o.Manifest == "" {
		return fmt.Errorf("sarif needs the manifest file the results point at")
	}
	rules := []sarifRule{}
	index := map[string]int{}
	results := []sarifResult{}
	for _, f := range r.Findings {
		i, ok := index[f.ID]
		if !ok {
			i = len(rules)
			index[f.ID] = i
			rules = append(rules, sarifRuleFor(f))
		}
		for _, a := range f.Affected {
			results = append(results, sarifResult{
				RuleID:    f.ID,
				RuleIndex: i,
				Level:     level(f.Severity),
				Message:   sarifText{fmt.Sprintf("%s@%s is affected by %s (%s).", a.Package, a.Version, f.ID, f.Severity)},
				Locations: []any{map[string]any{"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": o.Manifest, "uriBaseId": "%SRCROOT%"},
					"region":           map[string]any{"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 2},
				}}},
				PartialFingerprints: map[string]string{"primaryLocationLineHash": fingerprint(f.ID, a, o.Manifest)},
			})
		}
	}
	driver := map[string]any{"name": "CodeClarity", "informationUri": "https://github.com/CodeClarityCE", "rules": rules}
	if o.ToolVersion != "" {
		driver["version"] = o.ToolVersion
	}
	log := map[string]any{
		"$schema": sarifSchema,
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":              map[string]any{"driver": driver},
			"automationDetails": map[string]any{"id": "codeclarity/" + o.Manifest + "/"},
			"results":           results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

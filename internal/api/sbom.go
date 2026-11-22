package api

import (
	"context"
	"net/http"
	"net/url"
)

// Dependency is one package at one version in an analysis's SBOM.
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	// License is an SPDX expression or the package's own license text.
	License   string `json:"license"`
	Ecosystem string `json:"ecosystem"`
}

// SBOMWorkspaces lists the workspaces an analysis's SBOM has.
func (c *Client) SBOMWorkspaces(ctx context.Context, org, project, analysis string) ([]string, error) {
	var out struct {
		Data struct {
			Workspaces []string `json:"workspaces"`
		} `json:"data"`
	}
	path := orgPath(org, "projects", project, "analysis", analysis, "sbom", "workspaces")
	err := c.do(ctx, http.MethodGet, path, nil, nil, "", &out)
	return out.Data.Workspaces, err
}

// Dependencies lists every dependency of a workspace in an analysis's SBOM.
func (c *Client) Dependencies(ctx context.Context, org, project, analysis, workspace string) ([]Dependency, error) {
	path := orgPath(org, "projects", project, "analysis", analysis, "sbom")
	return all[Dependency](ctx, c, path, url.Values{"workspace": {workspace}})
}

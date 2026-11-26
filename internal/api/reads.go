package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

// getData reads a route whose answer is {data: ...} and returns data as the API sent it.
func (c *Client) getData(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, path, query, nil, "", &out)
	return out.Data, err
}

// AnalysisSummary is one analysis in a project's list of analyses.
type AnalysisSummary struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Branch        string `json:"branch"`
	Tag           string `json:"tag,omitempty"`
	CommitHash    string `json:"commit_hash,omitempty"`
	CreatedOn     string `json:"created_on"`
	EndedOn       string `json:"ended_on,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// Analyses lists the analyses of a project, in the order the API gives them.
func (c *Client) Analyses(ctx context.Context, org, project string) ([]AnalysisSummary, error) {
	return all[AnalysisSummary](ctx, c, orgPath(org, "projects", project, "analyses"), nil)
}

// Licenses lists the licenses an analysis found in a workspace, each with the dependencies under it.
func (c *Client) Licenses(ctx context.Context, org, project, analysis, workspace string) ([]json.RawMessage, error) {
	path := orgPath(org, "projects", project, "analysis", analysis, "licenses")
	return all[json.RawMessage](ctx, c, path, url.Values{"workspace": {workspace}})
}

// FixNext returns the organization's remediations ranked by how much each one fixes, at most limit of them.
func (c *Client) FixNext(ctx context.Context, org string, limit int) (json.RawMessage, error) {
	return c.getData(ctx, orgPath(org, "remediations", "fix-next"), url.Values{"limit": {strconv.Itoa(limit)}})
}

// Vulnerability returns what the organization knows of one vulnerability and the projects it affects.
func (c *Client) Vulnerability(ctx context.Context, org, vulnerability string) (json.RawMessage, error) {
	return c.getData(ctx, orgPath(org, "vulnerabilities", vulnerability), nil)
}

// Dependency returns one dependency (name@version) of an analysis's workspace.
func (c *Client) Dependency(ctx context.Context, org, project, analysis, workspace, dependency string) (json.RawMessage, error) {
	path := orgPath(org, "projects", project, "analysis", analysis, "sbom", "dependency")
	return c.getData(ctx, path, url.Values{"workspace": {workspace}, "dependency": {dependency}})
}

// DependencyGraph returns the dependencies that lead from the workspace to one dependency (name@version).
func (c *Client) DependencyGraph(ctx context.Context, org, project, analysis, workspace, dependency string) (json.RawMessage, error) {
	path := orgPath(org, "projects", project, "analysis", analysis, "sbom", "dependency", "graph")
	return c.getData(ctx, path, url.Values{"workspace": {workspace}, "dependency": {dependency}})
}

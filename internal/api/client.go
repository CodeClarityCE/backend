// Package api calls the CodeClarity API routes an Organization token may use.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ChunkSize is how much of an archive one upload request carries; the API takes up to 25 MB.
const ChunkSize = 20 << 20

// Client calls one instance's API with an Organization token.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New returns a client for the API at baseURL (for example https://host/api).
func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 2 * time.Minute},
	}
}

// Error is an error answer of the API.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("%s (HTTP %d, %s)", e.Message, e.Status, e.Code)
	case e.Message != "":
		return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status)
	default:
		return fmt.Sprintf("HTTP %d", e.Status)
	}
}

// IsStatus reports whether err is an API answer with that HTTP status.
func IsStatus(err error, status int) bool {
	var apiErr *Error
	return errors.As(err, &apiErr) && apiErr.Status == status
}

// do sends one request and decodes a JSON answer into out, when out is not nil.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string, out any) error {
	target := c.baseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var answer struct {
			Code    string `json:"error_code"`
			Message string `json:"error_message"`
		}
		_ = json.Unmarshal(data, &answer)
		return &Error{Status: resp.StatusCode, Code: answer.Code, Message: answer.Message}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: unexpected answer: %w", method, path, err)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, nil, bytes.NewReader(body), "application/json", out)
}

func orgPath(org string, parts ...string) string {
	escaped := []string{"/org", url.PathEscape(org)}
	for _, p := range parts {
		escaped = append(escaped, url.PathEscape(p))
	}
	return strings.Join(escaped, "/")
}

// page is one page of a paginated answer.
type page[T any] struct {
	Data       []T `json:"data"`
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

// all reads every page of a paginated route.
func all[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	var items []T
	for n := 0; ; n++ {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("page", strconv.Itoa(n))
		q.Set("entries_per_page", "100")
		var p page[T]
		if err := c.do(ctx, http.MethodGet, path, q, nil, "", &p); err != nil {
			return nil, err
		}
		items = append(items, p.Data...)
		if n+1 >= p.TotalPages {
			return items, nil
		}
	}
}

// Stage is one plugin of an analyzer.
type Stage struct {
	Name   string         `json:"name"`
	Config map[string]any `json:"config"`
}

// Analyzer is a named set of plugins an analysis runs.
type Analyzer struct {
	ID    string    `json:"id"`
	Name  string    `json:"name"`
	Steps [][]Stage `json:"steps"`
}

// CheckAccess asks for one analyzer, which any token of the organization may read.
func (c *Client) CheckAccess(ctx context.Context, org string) error {
	q := url.Values{"entries_per_page": {"1"}}
	return c.do(ctx, http.MethodGet, orgPath(org, "analyzers"), q, nil, "", &page[Analyzer]{})
}

// Analyzers lists the analyzers the organization can run.
func (c *Client) Analyzers(ctx context.Context, org string) ([]Analyzer, error) {
	return all[Analyzer](ctx, c, orgPath(org, "analyzers"), nil)
}

type created struct {
	ID string `json:"id"`
}

// CreateUploadProject creates a project whose source is an uploaded archive.
func (c *Client) CreateUploadProject(ctx context.Context, org, name, description string) (string, error) {
	var out created
	err := c.postJSON(ctx, orgPath(org, "projects"), map[string]string{"name": name, "description": description}, &out)
	return out.ID, err
}

// UploadArchive sends an archive to a project in chunks, as the web app does.
func (c *Client) UploadArchive(ctx context.Context, org, project, fileName string, archive []byte) error {
	for id, start := 0, 0; ; id, start = id+1, start+ChunkSize {
		end := min(start+ChunkSize, len(archive))
		last := end == len(archive)
		if err := c.uploadChunk(ctx, org, project, fileName, archive[start:end], id, last); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

func (c *Client) uploadChunk(ctx context.Context, org, project, fileName string, chunk []byte, id int, last bool) error {
	sum := sha256.Sum256(chunk)
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	fields := [][2]string{
		{"type", "source"},
		{"file_name", fileName},
		{"chunk", "true"},
		{"id", strconv.Itoa(id)},
		{"last", strconv.FormatBool(last)},
		{"hash", hex.EncodeToString(sum[:])},
	}
	for _, f := range fields {
		if err := form.WriteField(f[0], f[1]); err != nil {
			return err
		}
	}
	part, err := form.CreateFormFile("file", "blob")
	if err != nil {
		return err
	}
	if _, err := part.Write(chunk); err != nil {
		return err
	}
	if err := form.Close(); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPatch, orgPath(org, "file", project, "upload"), nil, &body, form.FormDataContentType(), nil)
}

// Project is a project of the organization: an upload (type FILE) or linked from GitHub or GitLab.
type Project struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	DefaultBranch string `json:"default_branch"`
}

// Project returns one project of the organization.
func (c *Client) Project(ctx context.Context, org, project string) (Project, error) {
	var out struct {
		Data Project `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, orgPath(org, "projects", project), nil, nil, "", &out)
	return out.Data, err
}

// AnalysisStart asks for an analysis of a project.
type AnalysisStart struct {
	AnalyzerID string                    `json:"analyzer_id"`
	Branch     string                    `json:"branch"`
	Config     map[string]map[string]any `json:"config"`
}

// StartAnalysis starts an analysis and returns its id.
func (c *Client) StartAnalysis(ctx context.Context, org, project string, start AnalysisStart) (string, error) {
	var out created
	err := c.postJSON(ctx, orgPath(org, "projects", project, "analyses"), start, &out)
	return out.ID, err
}

// Analysis is an analysis and how far it got.
type Analysis struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Analysis returns an analysis of a project.
func (c *Client) Analysis(ctx context.Context, org, project, analysis string) (Analysis, error) {
	var out struct {
		Data Analysis `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, orgPath(org, "projects", project, "analyses", analysis), nil, nil, "", &out)
	return out.Data, err
}

// Severity is a finding's score and class, such as CRITICAL.
type Severity struct {
	Score float64 `json:"Severity"`
	Class string  `json:"SeverityClass"`
}

// Affected is a dependency a finding affects.
type Affected struct {
	Dependency string `json:"AffectedDependency"`
	Version    string `json:"AffectedVersion"`
}

// Finding is one vulnerability of an analysis, with every dependency it affects.
type Finding struct {
	Vulnerability string     `json:"Vulnerability"`
	Severity      Severity   `json:"Severity"`
	Affected      []Affected `json:"Affected"`
	Description   string     `json:"Description"`
}

// Findings lists every vulnerability an analysis found in a workspace.
func (c *Client) Findings(ctx context.Context, org, project, analysis, workspace string) ([]Finding, error) {
	path := orgPath(org, "projects", project, "analysis", analysis, "vulnerabilities")
	return all[Finding](ctx, c, path, url.Values{"workspace": {workspace}})
}

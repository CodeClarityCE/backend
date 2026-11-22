package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	fakeOrg   = "11111111-1111-1111-1111-111111111111"
	goodToken = "ccot_good"
	readToken = "ccot_read"
	// linkedProject is a project imported from GitHub, with default branch develop.
	linkedProject = "project-linked"
)

// fakeAPI answers the API routes the CLI calls, as an instance with one organization would.
type fakeAPI struct {
	t      *testing.T
	server *httptest.Server

	mu sync.Mutex
	// statuses the next analysis reports, one per poll; the last one repeats.
	statuses []string
	findings []map[string]any
	// sbom holds each workspace's dependencies; nil answers 404, as an analysis with no SBOM does.
	sbom map[string][]map[string]any
	// What the CLI sent.
	requests      []string
	projectName   string
	uploaded      map[string][]byte
	startBody     map[string]any
	analysisPolls int
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, statuses: []string{"completed"}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAPI) url() string { return f.server.URL + "/api" }

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token != goodToken && token != readToken {
		reply(w, 401, map[string]any{"status_code": 401, "status": "failure", "error_code": "NotAuthenticated", "error_message": "Not authenticated"})
		return
	}
	prefix := "/api/org/" + fakeOrg
	if !strings.HasPrefix(r.URL.Path, prefix+"/") {
		reply(w, 403, map[string]any{"status_code": 403, "status": "failure", "error_code": "NotAuthorized", "error_message": "Not authorized"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	writes := r.Method != http.MethodGet
	if writes && token == readToken {
		reply(w, 403, map[string]any{"status_code": 403, "status": "failure", "error_code": "NotAuthorized", "error_message": "Not authorized"})
		return
	}

	switch {
	case r.Method == http.MethodGet && path == "/analyzers":
		reply(w, 200, map[string]any{"data": []map[string]any{
			{"id": "analyzer-php", "name": "PHP Analyzer", "steps": [][]map[string]any{{{"name": "php-sbom", "version": "1", "config": map[string]any{"project": map[string]any{}}}}}},
			{"id": "analyzer-default", "name": "Default Analyzer", "steps": [][]map[string]any{
				{{"name": "js-sbom", "version": "1", "config": map[string]any{"project": map[string]any{}}}},
				{
					{"name": "vuln-finder", "version": "1", "config": map[string]any{"vulnerabilityPolicy": map[string]any{}}},
					{"name": "license-finder", "version": "1", "config": map[string]any{"licensePolicy": map[string]any{}}},
				},
			}},
		}, "page": 0, "total_pages": 1})
	case r.Method == http.MethodPost && path == "/projects":
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.projectName = body["name"]
		reply(w, 201, map[string]any{"status_code": 201, "status": "success", "id": "project-1"})
	case r.Method == http.MethodPatch && path == "/file/project-1/upload":
		f.receiveChunk(w, r)
	case r.Method == http.MethodGet && path == "/projects/project-1":
		reply(w, 200, map[string]any{"data": map[string]any{"id": "project-1", "name": "shop-front", "type": "FILE", "default_branch": ""}})
	case r.Method == http.MethodGet && path == "/projects/"+linkedProject:
		reply(w, 200, map[string]any{"data": map[string]any{
			"id": linkedProject, "name": "acme/shop-front", "type": "GITHUB", "default_branch": "develop",
			"url": "https://github.com/acme/shop-front",
		}})
	case r.Method == http.MethodPost && (path == "/projects/project-1/analyses" || path == "/projects/"+linkedProject+"/analyses"):
		_ = json.NewDecoder(r.Body).Decode(&f.startBody)
		reply(w, 201, map[string]any{"status_code": 201, "status": "success", "id": "analysis-1"})
	case r.Method == http.MethodGet && path == "/projects/"+linkedProject+"/analyses/analysis-1":
		reply(w, 200, map[string]any{"data": map[string]any{"id": "analysis-1", "status": "completed"}})
	case r.Method == http.MethodGet && path == "/projects/project-1/analyses/analysis-1":
		status := f.statuses[min(f.analysisPolls, len(f.statuses)-1)]
		f.analysisPolls++
		reply(w, 200, map[string]any{"data": map[string]any{"id": "analysis-1", "status": status}})
	case r.Method == http.MethodGet && (path == "/projects/project-1/analysis/analysis-1/vulnerabilities" || path == "/projects/"+linkedProject+"/analysis/analysis-1/vulnerabilities"):
		f.replyFindings(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/projects/project-1/analysis/analysis-1/sbom"):
		f.replySBOM(w, r, strings.TrimPrefix(path, "/projects/project-1/analysis/analysis-1/sbom"))
	default:
		reply(w, 404, map[string]any{"status_code": 404, "status": "failure", "error_code": "EntityNotFound", "error_message": "Not found"})
	}
}

// receiveChunk appends one uploaded chunk to its file, as the API does.
func (f *fakeAPI) receiveChunk(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	if err := r.ParseMultipartForm(64 << 20); err != nil { //nolint:gosec // a test server; the body is capped just above
		reply(w, 400, map[string]any{"error_message": err.Error()})
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		reply(w, 400, map[string]any{"error_message": err.Error()})
		return
	}
	data, _ := io.ReadAll(file)
	if f.uploaded == nil {
		f.uploaded = map[string][]byte{}
	}
	name := r.FormValue("file_name")
	f.uploaded[name] = append(f.uploaded[name], data...)
	w.WriteHeader(200)
}

// replyFindings serves the findings two per page, so the CLI must read every page.
func (f *fakeAPI) replyFindings(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	const perPage = 2
	pages := max(1, (len(f.findings)+perPage-1)/perPage)
	start := min(page*perPage, len(f.findings))
	end := min(start+perPage, len(f.findings))
	reply(w, 200, map[string]any{
		"data": f.findings[start:end], "page": page, "total_pages": pages,
		"total_entries": len(f.findings), "entries_per_page": perPage,
	})
}

// uploadedFiles lists the files inside the uploaded archive.
func (f *fakeAPI) uploadedFiles() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	files := map[string]string{}
	for name, data := range f.uploaded {
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			f.t.Fatalf("upload %s is not a zip: %v", name, err)
		}
		for _, entry := range reader.File {
			rc, _ := entry.Open()
			content, _ := io.ReadAll(rc)
			_ = rc.Close()
			files[entry.Name] = string(content)
		}
	}
	return files
}

// count returns how many requests matched method and path.
func (f *fakeAPI) count(method, path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, req := range f.requests {
		if req == fmt.Sprintf("%s /api/org/%s%s", method, fakeOrg, path) {
			n++
		}
	}
	return n
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

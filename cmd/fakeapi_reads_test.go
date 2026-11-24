package cmd

import (
	"net/http"
	"strconv"
)

func notFound(w http.ResponseWriter, code, message string) {
	reply(w, 404, map[string]any{"status_code": 404, "status": "failure", "error_code": code, "error_message": message})
}

// replyAnalyses serves project-1's two analyses in one page.
func (f *fakeAPI) replyAnalyses(w http.ResponseWriter, _ *http.Request) {
	reply(w, 200, map[string]any{"data": []map[string]any{
		{"id": "analysis-1", "status": "completed", "branch": "main", "created_on": "2026-11-23T10:00:00.000Z", "config": map[string]any{"js-sbom": map[string]any{}}},
		{"id": "analysis-0", "status": "failure", "branch": "main", "created_on": "2026-11-22T10:00:00.000Z", "failure_reason": "clone failed"},
	}, "page": 0, "total_pages": 1})
}

// replyLicenses serves the root workspace's licenses two per page.
func (f *fakeAPI) replyLicenses(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("workspace") != "." {
		notFound(w, "UnknownWorkspace", "Unknown workspace")
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	const perPage = 2
	pages := max(1, (len(f.licenses)+perPage-1)/perPage)
	start := min(page*perPage, len(f.licenses))
	end := min(start+perPage, len(f.licenses))
	reply(w, 200, map[string]any{"data": f.licenses[start:end], "page": page, "total_pages": pages})
}

// replyDependency knows lodash@4.17.20 in the root workspace, pulled in by express.
func (f *fakeAPI) replyDependency(w http.ResponseWriter, r *http.Request, route string) {
	q := r.URL.Query()
	if q.Get("workspace") != "." || q.Get("dependency") != "lodash@4.17.20" {
		notFound(w, "DependencyNotFound", "Dependency not found")
		return
	}
	switch route {
	case "":
		reply(w, 200, map[string]any{"data": map[string]any{"name": "lodash", "version": "4.17.20", "transitive": true}})
	case "/graph":
		reply(w, 200, map[string]any{"data": []map[string]any{
			{"id": "express@4.18.0", "parentIds": []string{}},
			{"id": "lodash@4.17.20", "parentIds": []string{"express@4.18.0"}},
		}})
	default:
		notFound(w, "EntityNotFound", "Not found")
	}
}

// replyFixNext serves one remediation and records the query.
func (f *fakeAPI) replyFixNext(w http.ResponseWriter, r *http.Request) {
	f.fixNextQuery = r.URL.RawQuery
	reply(w, 200, map[string]any{"data": []map[string]any{{
		"kind": "upgrade_direct", "package": "lodash", "target_version": "4.17.21", "potentially_breaking": false,
		"vulnerability_id": "CVE-2021-23337", "vulnerability_count": 2, "project_count": 1,
		"remediations": []map[string]any{{"project_id": "project-1", "workspace": ".", "command": "npm install lodash@4.17.21"}},
	}}})
}

// replyVulnerability knows CVE-2021-23337 only.
func (f *fakeAPI) replyVulnerability(w http.ResponseWriter, id string) {
	if id != "CVE-2021-23337" {
		notFound(w, "EntityNotFound", "Not found")
		return
	}
	reply(w, 200, map[string]any{"data": map[string]any{
		"vulnerability_id": id, "severity_class": "HIGH", "severity_score": 7.2,
		"details":  map[string]any{"description": "Command injection in lodash"},
		"projects": []map[string]any{{"project_id": "project-1", "project_name": "shop-front"}},
	}})
}

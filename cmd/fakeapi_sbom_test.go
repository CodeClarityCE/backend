package cmd

import (
	"net/http"
	"slices"
	"strconv"
)

// replySBOM serves the SBOM workspaces, and each workspace's dependencies two per page.
func (f *fakeAPI) replySBOM(w http.ResponseWriter, r *http.Request, route string) {
	if f.sbom == nil {
		reply(w, 404, map[string]any{"status_code": 404, "status": "failure", "error_code": "PluginResultNotAvailable", "error_message": "Plugin result not available"})
		return
	}
	if route == "/workspaces" {
		names := make([]string, 0, len(f.sbom))
		for name := range f.sbom {
			names = append(names, name)
		}
		slices.Sort(names)
		reply(w, 200, map[string]any{"data": map[string]any{"workspaces": names, "package_manager": "NPM"}})
		return
	}
	deps, ok := f.sbom[r.URL.Query().Get("workspace")]
	if route != "" || !ok {
		reply(w, 404, map[string]any{"status_code": 404, "status": "failure", "error_code": "UnknownWorkspace", "error_message": "Unknown workspace"})
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	const perPage = 2
	pages := max(1, (len(deps)+perPage-1)/perPage)
	start := min(page*perPage, len(deps))
	end := min(start+perPage, len(deps))
	reply(w, 200, map[string]any{"data": deps[start:end], "page": page, "total_pages": pages, "total_entries": len(deps)})
}

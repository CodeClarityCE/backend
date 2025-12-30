package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"codeclarity.io/internal/auth"
	"codeclarity.io/internal/config"
)

// Client is the API client for CodeClarity
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// NewClient creates a new API client
func NewClient(baseURL string) *Client {
	// Allow insecure TLS for local development
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: os.Getenv("CODECLARITY_ALLOW_INSECURE") == "true",
		},
	}

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// NewAuthenticatedClient creates a new authenticated API client
func NewAuthenticatedClient() (*Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}

	client := NewClient(cfg.APIBaseURL)

	token, err := auth.GetAuthToken()
	if err != nil {
		// Check if we need to refresh
		if auth.NeedsRefresh() {
			refreshToken, err := auth.GetRefreshToken()
			if err != nil {
				return nil, err
			}
			newTokens, err := client.RefreshToken(refreshToken)
			if err != nil {
				return nil, fmt.Errorf("failed to refresh token: %w", err)
			}
			// Save the new tokens
			tokens, _ := auth.LoadTokens()
			tokens.AccessToken = newTokens.Token
			tokens.RefreshToken = newTokens.RefreshToken
			tokens.TokenExpiry = newTokens.TokenExpiry
			tokens.RefreshTokenExpiry = newTokens.RefreshTokenExpiry
			if err := auth.SaveTokens(tokens); err != nil {
				return nil, err
			}
			token = newTokens.Token
		} else {
			return nil, err
		}
	}

	client.SetToken(token)
	return client, nil
}

// SetToken sets the authentication token
func (c *Client) SetToken(token string) {
	c.token = token
}

// apiResponseWrapper is used to unwrap the standard API response format
type apiResponseWrapper struct {
	StatusCode int             `json:"status_code"`
	Status     string          `json:"status"`
	Data       json.RawMessage `json:"data"`
}

// doRequest performs an HTTP request
func (c *Client) doRequest(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	// Split path and query string to avoid encoding the query string
	basePath := path
	queryString := ""
	if idx := strings.Index(path, "?"); idx != -1 {
		basePath = path[:idx]
		queryString = path[idx:]
	}

	reqURL, err := url.JoinPath(c.baseURL, basePath)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}
	reqURL += queryString

	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.Unmarshal(respBody, &apiErr); err != nil {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		apiErr.StatusCode = resp.StatusCode
		return fmt.Errorf("API error: %s", apiErr.String())
	}

	if result != nil && len(respBody) > 0 {
		// Check if response is wrapped in standard API format {"status_code":..., "data":...}
		var wrapper apiResponseWrapper
		if err := json.Unmarshal(respBody, &wrapper); err == nil && wrapper.Data != nil {
			// Check if data is an array (paginated response) or object (single item)
			// For paginated responses, the wrapper fields are at the same level as pagination
			// For single item responses, data contains the actual item
			trimmed := bytes.TrimSpace(wrapper.Data)
			if len(trimmed) > 0 && trimmed[0] == '[' {
				// Data is an array - this is a paginated response, parse directly
				if err := json.Unmarshal(respBody, result); err != nil {
					return fmt.Errorf("failed to parse paginated response: %w", err)
				}
			} else {
				// Data is an object - unwrap it
				if err := json.Unmarshal(wrapper.Data, result); err != nil {
					return fmt.Errorf("failed to parse response data: %w", err)
				}
			}
		} else {
			// Try direct parsing (for responses without wrapper)
			if err := json.Unmarshal(respBody, result); err != nil {
				return fmt.Errorf("failed to parse response: %w", err)
			}
		}
	}

	return nil
}

// Auth endpoints

// Authenticate authenticates with email and password
func (c *Client) Authenticate(email, password string) (*AuthResponse, error) {
	req := AuthRequest{
		Email:    email,
		Password: password,
	}

	var resp AuthResponse
	if err := c.doRequest("POST", "/auth/authenticate", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// RefreshToken refreshes the access token
func (c *Client) RefreshToken(refreshToken string) (*AuthResponse, error) {
	req := RefreshRequest{
		RefreshToken: refreshToken,
	}

	var resp AuthResponse
	if err := c.doRequest("POST", "/auth/refresh", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetCurrentUser returns the current authenticated user
func (c *Client) GetCurrentUser() (*User, error) {
	var user User
	if err := c.doRequest("GET", "/auth/user", nil, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

// Analyzer endpoints

// ListAnalyzers lists analyzers for an organization
func (c *Client) ListAnalyzers(orgID string, page, perPage int) (*PaginatedResponse[Analyzer], error) {
	path := fmt.Sprintf("/org/%s/analyzers?page=%d&entries_per_page=%d", orgID, page, perPage)

	var resp PaginatedResponse[Analyzer]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetAnalyzer gets an analyzer by ID
func (c *Client) GetAnalyzer(orgID, analyzerID string) (*Analyzer, error) {
	path := fmt.Sprintf("/org/%s/analyzers/%s", orgID, analyzerID)

	var resp SingleResponse[Analyzer]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp.Data, nil
}

// CreateAnalyzer creates a new analyzer
func (c *Client) CreateAnalyzer(orgID string, req AnalyzerCreateRequest) (string, error) {
	path := fmt.Sprintf("/org/%s/analyzers", orgID)

	var resp CreatedResponse
	if err := c.doRequest("POST", path, req, &resp); err != nil {
		return "", err
	}

	return resp.ID, nil
}

// Project endpoints

// ListProjects lists projects for an organization
func (c *Client) ListProjects(orgID string, page, perPage int, search string) (*PaginatedResponse[Project], error) {
	path := fmt.Sprintf("/org/%s/projects?page=%d&entries_per_page=%d", orgID, page, perPage)
	if search != "" {
		path += "&search_key=" + url.QueryEscape(search)
	}

	var resp PaginatedResponse[Project]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetProject gets a project by ID
func (c *Client) GetProject(orgID, projectID string) (*Project, error) {
	path := fmt.Sprintf("/org/%s/projects/%s", orgID, projectID)

	var resp SingleResponse[Project]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp.Data, nil
}

// ImportProject imports a new project
func (c *Client) ImportProject(orgID string, req ProjectImportRequest) (string, error) {
	path := fmt.Sprintf("/org/%s/projects", orgID)

	var resp CreatedResponse
	if err := c.doRequest("POST", path, req, &resp); err != nil {
		return "", err
	}

	return resp.ID, nil
}

// Analysis endpoints

// ListAnalyses lists analyses for a project
func (c *Client) ListAnalyses(orgID, projectID string, page, perPage int) (*PaginatedResponse[Analysis], error) {
	path := fmt.Sprintf("/org/%s/projects/%s/analyses?page=%d&entries_per_page=%d", orgID, projectID, page, perPage)

	var resp PaginatedResponse[Analysis]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetAnalysis gets an analysis by ID
func (c *Client) GetAnalysis(orgID, projectID, analysisID string) (*Analysis, error) {
	path := fmt.Sprintf("/org/%s/projects/%s/analyses/%s", orgID, projectID, analysisID)

	var resp SingleResponse[Analysis]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp.Data, nil
}

// StartAnalysis starts a new analysis
func (c *Client) StartAnalysis(orgID, projectID string, req AnalysisCreateRequest) (string, error) {
	path := fmt.Sprintf("/org/%s/projects/%s/analyses", orgID, projectID)

	var resp CreatedResponse
	if err := c.doRequest("POST", path, req, &resp); err != nil {
		return "", err
	}

	return resp.ID, nil
}

// Results endpoints

// GetVulnerabilityStats gets vulnerability statistics for an analysis
func (c *Client) GetVulnerabilityStats(orgID, projectID, analysisID, workspace string) (*VulnerabilityStats, error) {
	// Default workspace to "." (root) if not specified
	if workspace == "" {
		workspace = "."
	}
	path := fmt.Sprintf("/org/%s/projects/%s/analysis/%s/vulnerabilities/stats?workspace=%s", orgID, projectID, analysisID, url.QueryEscape(workspace))

	// doRequest already unwraps the "data" field, so parse directly into stats
	var resp VulnerabilityStats
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetSBOMStats gets SBOM statistics for an analysis
func (c *Client) GetSBOMStats(orgID, projectID, analysisID, workspace string) (*SBOMStats, error) {
	// Default workspace to "." (root) if not specified
	if workspace == "" {
		workspace = "."
	}
	path := fmt.Sprintf("/org/%s/projects/%s/analysis/%s/sbom/stats?workspace=%s", orgID, projectID, analysisID, url.QueryEscape(workspace))

	// doRequest already unwraps the "data" field, so parse directly into stats
	var resp SBOMStats
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// GetLicenseStats gets license statistics for an analysis
func (c *Client) GetLicenseStats(orgID, projectID, analysisID, workspace string) (*LicenseStats, error) {
	path := fmt.Sprintf("/org/%s/projects/%s/analysis/%s/licenses/stats", orgID, projectID, analysisID)
	if workspace != "" {
		path += "?workspace=" + url.QueryEscape(workspace)
	}

	var resp SingleResponse[LicenseStats]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp.Data, nil
}

// GetVulnerabilities gets the list of vulnerabilities for an analysis
func (c *Client) GetVulnerabilities(orgID, projectID, analysisID, workspace string, page, perPage int) (*PaginatedResponse[Vulnerability], error) {
	path := fmt.Sprintf("/org/%s/projects/%s/analysis/%s/vulnerabilities?page=%d&entries_per_page=%d", orgID, projectID, analysisID, page, perPage)
	if workspace != "" {
		path += "&workspace=" + url.QueryEscape(workspace)
	}

	var resp PaginatedResponse[Vulnerability]
	if err := c.doRequest("GET", path, nil, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

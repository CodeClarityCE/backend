package api

import (
	"fmt"
	"time"
)

// AuthRequest represents authentication credentials
type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Token              string    `json:"token"`
	RefreshToken       string    `json:"refresh_token"`
	TokenExpiry        time.Time `json:"token_expiry"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
}

// RefreshRequest represents a token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// DefaultOrg represents the user's default organization
type DefaultOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// User represents a CodeClarity user
type User struct {
	ID         string      `json:"id"`
	Email      string      `json:"email"`
	Handle     string      `json:"handle"`
	FirstName  string      `json:"first_name"`
	LastName   string      `json:"last_name"`
	DefaultOrg *DefaultOrg `json:"default_org,omitempty"`
	Activated  bool        `json:"activated"`
}

// GetDefaultOrgID returns the user's default org ID if available
func (u *User) GetDefaultOrgID() string {
	if u.DefaultOrg != nil {
		return u.DefaultOrg.ID
	}
	return ""
}

// Organization represents an organization
type Organization struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedOn   time.Time `json:"created_on"`
}

// Analyzer represents an analyzer configuration
type Analyzer struct {
	ID                 string     `json:"id"`
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	CreatedOn          time.Time  `json:"created_on"`
	Steps              [][]Stage  `json:"steps"`
	SupportedLanguages []string   `json:"supported_languages,omitempty"`
	LanguageConfig     any        `json:"language_config,omitempty"`
	Logo               string     `json:"logo,omitempty"`
	Global             bool       `json:"global"`
}

// Stage represents an analysis stage
type Stage struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Config  map[string]any `json:"config,omitempty"`
}

// AnalyzerCreateRequest represents the request to create an analyzer
type AnalyzerCreateRequest struct {
	Name               string     `json:"name"`
	Description        string     `json:"description"`
	Steps              [][]Stage  `json:"steps"`
	SupportedLanguages []string   `json:"supported_languages,omitempty"`
	LanguageConfig     any        `json:"language_config,omitempty"`
	Logo               string     `json:"logo,omitempty"`
}

// Project represents a CodeClarity project
type Project struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	URL                 string    `json:"url"`
	Type                string    `json:"type"`
	IntegrationProvider string    `json:"integration_provider"`
	IntegrationType     string    `json:"integration_type"`
	DefaultBranch       string    `json:"default_branch"`
	Downloaded          bool      `json:"downloaded"`
	AddedOn             time.Time `json:"added_on"`
	Invalid             bool      `json:"invalid"`
}

// ProjectImportRequest represents the request to import a project
type ProjectImportRequest struct {
	IntegrationID string `json:"integration_id"`
	URL           string `json:"url"`
	Name          string `json:"name,omitempty"`
	Description   string `json:"description,omitempty"`
}

// Analysis represents an analysis run
type Analysis struct {
	ID               string           `json:"id"`
	AnalyzerID       string           `json:"analyzerId"`
	ProjectID        string           `json:"projectId"`
	OrganizationID   string           `json:"organizationId"`
	Status           AnalysisStatus   `json:"status"`
	Stage            int              `json:"stage"`
	Steps            [][]AnalysisStep `json:"steps"`
	Branch           string           `json:"branch"`
	Tag              string           `json:"tag,omitempty"`
	CommitHash       string           `json:"commit_hash,omitempty"`
	Config           map[string]any   `json:"config,omitempty"`
	CreatedOn        time.Time        `json:"created_on"`
	StartedOn        *time.Time       `json:"started_on,omitempty"`
	EndedOn          *time.Time       `json:"ended_on,omitempty"`
	ScheduleType     string           `json:"schedule_type,omitempty"`
	NextScheduledRun *time.Time       `json:"next_scheduled_run,omitempty"`
	IsActive         bool             `json:"is_active"`
}

// AnalysisStatus represents the status of an analysis
type AnalysisStatus string

const (
	StatusRequested AnalysisStatus = "requested"
	StatusTriggered AnalysisStatus = "triggered"
	StatusStarted   AnalysisStatus = "started"
	StatusFinished  AnalysisStatus = "finished"
	StatusCompleted AnalysisStatus = "completed"
	StatusFailed    AnalysisStatus = "failed"
	StatusSuccess   AnalysisStatus = "success"
)

// AnalysisStep represents a step in an analysis
type AnalysisStep struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

// AnalysisCreateRequest represents the request to start an analysis
type AnalysisCreateRequest struct {
	AnalyzerID       string                    `json:"analyzer_id"`
	Config           map[string]map[string]any `json:"config"`
	Branch           string                    `json:"branch"`
	Tag              string                    `json:"tag,omitempty"`
	CommitHash       string                    `json:"commit_hash,omitempty"`
	Languages        []string                  `json:"languages,omitempty"`
	ScheduleType     string                    `json:"schedule_type,omitempty"`
	NextScheduledRun string                    `json:"next_scheduled_run,omitempty"`
	IsActive         bool                      `json:"is_active"`
}

// VulnerabilityStats represents vulnerability statistics
type VulnerabilityStats struct {
	Total    int `json:"number_of_vulnerabilities"`
	Critical int `json:"number_of_critical"`
	High     int `json:"number_of_high"`
	Medium   int `json:"number_of_medium"`
	Low      int `json:"number_of_low"`
	None     int `json:"number_of_none"`
}

// SBOMStats represents SBOM statistics
type SBOMStats struct {
	TotalDependencies      int `json:"number_of_dependencies"`
	DirectDependencies     int `json:"number_of_direct_dependencies"`
	TransitiveDependencies int `json:"number_of_transitive_dependencies"`
}

// LicenseStats represents license statistics
type LicenseStats struct {
	Total        int            `json:"total"`
	ByLicense    map[string]int `json:"by_license,omitempty"`
	ByCompliance map[string]int `json:"by_compliance,omitempty"`
}

// Vulnerability represents a merged vulnerability from analysis results
type Vulnerability struct {
	ID          string           `json:"Id"`
	Affected    []AffectedVuln   `json:"Affected"`
	Severity    Severity         `json:"Severity"`
	Description string           `json:"Description"`
	EPSS        *EPSS            `json:"EPSS,omitempty"`
}

// AffectedVuln represents an affected dependency
type AffectedVuln struct {
	AffectedDependency string   `json:"AffectedDependency"`
	AffectedVersion    string   `json:"AffectedVersion"`
	VulnerabilityId    string   `json:"VulnerabilityId"`
	Severity           Severity `json:"Severity"`
}

// Severity represents CVSS severity information
type Severity struct {
	Severity      float64 `json:"Severity"`
	SeverityClass string  `json:"SeverityClass"`
	SeverityType  string  `json:"SeverityType"`
	Vector        string  `json:"Vector"`
}

// EPSS represents Exploit Prediction Scoring System data
type EPSS struct {
	Score      float64 `json:"Score"`
	Percentile float64 `json:"Percentile"`
}

// PaginatedResponse represents a paginated API response
// Includes wrapper fields (status_code, status) since the API returns them at the same level
type PaginatedResponse[T any] struct {
	// Wrapper fields
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	// Pagination fields
	Data           []T `json:"data"`
	Page           int `json:"page"`
	EntryCount     int `json:"entry_count"`
	EntriesPerPage int `json:"entries_per_page"`
	TotalEntries   int `json:"total_entries"`
	TotalPages     int `json:"total_pages"`
	MatchingCount  int `json:"matching_count"`
}

// APIResponse represents the standard API response wrapper
type APIResponse[T any] struct {
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	Data       T      `json:"data"`
}

// SingleResponse represents a single item response (used within APIResponse.Data)
type SingleResponse[T any] struct {
	Data T `json:"data"`
}

// CreatedResponse represents a created resource response
type CreatedResponse struct {
	ID string `json:"id"`
}

// APIError represents an API error response
type APIError struct {
	StatusCode int    `json:"status_code"`
	Status     string `json:"status"`
	ErrorCode  string `json:"error_code,omitempty"`
	Message    string `json:"message,omitempty"`
}

func (e *APIError) String() string {
	if e.ErrorCode != "" {
		if e.Message != "" {
			return fmt.Sprintf("%s: %s", e.ErrorCode, e.Message)
		}
		return e.ErrorCode
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

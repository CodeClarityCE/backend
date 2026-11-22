// Package session stores where the CLI is logged in, and the last analysis it started.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Environment variables that override the stored session.
const (
	URLEnv   = "CODECLARITY_URL"
	OrgEnv   = "CODECLARITY_ORG"
	TokenEnv = "CODECLARITY_TOKEN" //nolint:gosec // the variable's name, not a token
)

const (
	dirName         = ".codeclarity"
	credentialsName = "credentials.json"
	lastName        = "last-analysis.json"
)

// Session is the instance, organization and Organization token the CLI uses.
type Session struct {
	URL            string `json:"url"`
	OrganizationID string `json:"organization_id"`
	Token          string `json:"token"`
}

// Analysis names an analysis of a project.
type Analysis struct {
	ProjectID  string `json:"project_id"`
	AnalysisID string `json:"analysis_id"`
}

// ErrNotLoggedIn means neither a stored session nor the environment gives a complete one.
var ErrNotLoggedIn = errors.New("not logged in: run 'codeclarity login', or set " + URLEnv + ", " + OrgEnv + " and " + TokenEnv)

func dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, dirName), nil
}

// Load returns the stored session with any environment variable taking precedence.
func Load() (Session, error) {
	var s Session
	if err := readJSON(credentialsName, &s); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Session{}, err
	}
	override(&s.URL, URLEnv)
	override(&s.OrganizationID, OrgEnv)
	override(&s.Token, TokenEnv)
	if s.URL == "" || s.OrganizationID == "" || s.Token == "" {
		return Session{}, ErrNotLoggedIn
	}
	return s, nil
}

func override(field *string, env string) {
	if v := os.Getenv(env); v != "" {
		*field = v
	}
}

// Save stores the session, readable by the user only.
func Save(s Session) error {
	return writeJSON(credentialsName, s)
}

// Clear forgets the stored session and last analysis.
func Clear() error {
	d, err := dir()
	if err != nil {
		return err
	}
	for _, name := range []string{credentialsName, lastName} {
		if err := os.Remove(filepath.Join(d, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// SaveLastAnalysis remembers the analysis analyze started, for results.
func SaveLastAnalysis(a Analysis) error {
	return writeJSON(lastName, a)
}

// LastAnalysis returns the analysis analyze last started.
func LastAnalysis() (Analysis, error) {
	var a Analysis
	if err := readJSON(lastName, &a); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Analysis{}, errors.New("no analysis yet: run 'codeclarity analyze', or pass --project and --analysis")
		}
		return Analysis{}, err
	}
	return a, nil
}

func readJSON(name string, v any) error {
	d, err := dir()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(d, name)) //nolint:gosec // a fixed file in the user's config dir
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func writeJSON(name string, v any) error {
	d, err := dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	path := filepath.Join(d, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	// WriteFile keeps the mode of an existing file, so set it again.
	return os.Chmod(path, 0o600)
}

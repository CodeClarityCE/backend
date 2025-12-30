package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"codeclarity.io/internal/config"
	"gopkg.in/yaml.v3"
)

const (
	CredentialsFileName = "credentials.yaml"
	FilePermissions     = 0600
	APIKeyEnvVar        = "CODECLARITY_API_KEY"
)

// TokenStore represents stored authentication tokens
type TokenStore struct {
	AccessToken        string    `yaml:"access_token"`
	RefreshToken       string    `yaml:"refresh_token"`
	TokenExpiry        time.Time `yaml:"token_expiry"`
	RefreshTokenExpiry time.Time `yaml:"refresh_token_expiry"`
	UserID             string    `yaml:"user_id"`
	Email              string    `yaml:"email"`
}

// GetCredentialsPath returns the path to the credentials file
func GetCredentialsPath() (string, error) {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, CredentialsFileName), nil
}

// LoadTokens loads tokens from disk
func LoadTokens() (*TokenStore, error) {
	path, err := GetCredentialsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not authenticated: run 'codeclarity login'")
		}
		return nil, err
	}

	tokens := &TokenStore{}
	if err := yaml.Unmarshal(data, tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

// SaveTokens saves tokens to disk with secure permissions
func SaveTokens(tokens *TokenStore) error {
	if err := config.EnsureConfigDir(); err != nil {
		return err
	}

	path, err := GetCredentialsPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(tokens)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, FilePermissions)
}

// ClearTokens removes the stored credentials
func ClearTokens() error {
	path, err := GetCredentialsPath()
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GetAuthToken returns the current auth token, checking env var first
func GetAuthToken() (string, error) {
	// Check environment variable first (CI/CD mode)
	if apiKey := os.Getenv(APIKeyEnvVar); apiKey != "" {
		return apiKey, nil
	}

	// Check stored tokens
	tokens, err := LoadTokens()
	if err != nil {
		return "", err
	}

	// Check if token is expired
	if time.Now().After(tokens.TokenExpiry) {
		if time.Now().After(tokens.RefreshTokenExpiry) {
			return "", fmt.Errorf("session expired: run 'codeclarity login'")
		}
		return "", fmt.Errorf("token expired, refresh required")
	}

	return tokens.AccessToken, nil
}

// IsAuthenticated checks if the user is authenticated
func IsAuthenticated() bool {
	// Check env var
	if os.Getenv(APIKeyEnvVar) != "" {
		return true
	}

	tokens, err := LoadTokens()
	if err != nil {
		return false
	}

	// Check if refresh token is still valid
	return time.Now().Before(tokens.RefreshTokenExpiry)
}

// NeedsRefresh checks if the token needs to be refreshed
func NeedsRefresh() bool {
	tokens, err := LoadTokens()
	if err != nil {
		return false
	}

	// Refresh if token expires in less than 5 minutes
	return time.Now().Add(5 * time.Minute).After(tokens.TokenExpiry)
}

// GetRefreshToken returns the refresh token
func GetRefreshToken() (string, error) {
	tokens, err := LoadTokens()
	if err != nil {
		return "", err
	}
	return tokens.RefreshToken, nil
}

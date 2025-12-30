package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	ConfigDir      = ".codeclarity"
	ConfigFileName = "config.yaml"
	DirPermissions = 0700
)

// Config represents the CLI configuration
type Config struct {
	APIBaseURL   string `yaml:"api_base_url"`
	DefaultOrgID string `yaml:"default_org_id"`
	OutputFormat string `yaml:"output_format"`
	Debug        bool   `yaml:"debug"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		APIBaseURL:   "https://localhost/api",
		OutputFormat: "table",
		Debug:        false,
	}
}

// GetConfigDir returns the path to the config directory
func GetConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ConfigDir), nil
}

// GetConfigPath returns the path to the config file
func GetConfigPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, ConfigFileName), nil
}

// EnsureConfigDir creates the config directory if it doesn't exist
func EnsureConfigDir() error {
	configDir, err := GetConfigDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(configDir, DirPermissions)
}

// Load loads the configuration from disk
func Load() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Apply defaults for missing values
	if config.APIBaseURL == "" {
		config.APIBaseURL = "https://localhost/api"
	}
	if config.OutputFormat == "" {
		config.OutputFormat = "table"
	}

	return config, nil
}

// Save saves the configuration to disk
func Save(config *Config) error {
	if err := EnsureConfigDir(); err != nil {
		return err
	}

	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

// Set sets a configuration value by key
func (c *Config) Set(key, value string) bool {
	switch key {
	case "api_base_url", "api-url", "url":
		c.APIBaseURL = value
	case "default_org_id", "org", "org_id":
		c.DefaultOrgID = value
	case "output_format", "output", "format":
		c.OutputFormat = value
	case "debug":
		c.Debug = value == "true" || value == "1"
	default:
		return false
	}
	return true
}

// Get returns a configuration value by key
func (c *Config) Get(key string) string {
	switch key {
	case "api_base_url", "api-url", "url":
		return c.APIBaseURL
	case "default_org_id", "org", "org_id":
		return c.DefaultOrgID
	case "output_format", "output", "format":
		return c.OutputFormat
	case "debug":
		if c.Debug {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

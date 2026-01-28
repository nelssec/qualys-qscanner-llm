package config

import (
	"fmt"
	"strings"

	"github.com/nelssec/qualys-qscanner-llm/internal/credentials"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	AnthropicAPIKey string `envconfig:"ANTHROPIC_API_KEY"`

	QualysUsername     string `envconfig:"QUALYS_USERNAME"`
	QualysPassword     string `envconfig:"QUALYS_PASSWORD"`
	QualysClientID     string `envconfig:"QUALYS_CLIENT_ID"`
	QualysClientSecret string `envconfig:"QUALYS_CLIENT_SECRET"`
	QualysBearerToken  string `envconfig:"QUALYS_BEARER_TOKEN"`
	QualysPOD          string `envconfig:"QUALYS_POD" default:"US2"`
	QualysAPIURL       string `envconfig:"QUALYS_API_URL"`

	QScannerPath   string `envconfig:"QSCANNER_PATH" default:"./qscanner-bin"`
	LogLevel       string `envconfig:"LOG_LEVEL" default:"info"`
	ServerPort     int    `envconfig:"SERVER_PORT" default:"8080"`
	APIKeyRequired bool   `envconfig:"API_KEY_REQUIRED" default:"false"`
	APIKeys        string `envconfig:"API_KEYS"`

	OllamaURL     string `envconfig:"OLLAMA_URL" default:"http://localhost:11434"`
	OllamaModel   string `envconfig:"OLLAMA_MODEL" default:"qwen2.5:7b"`
	PreferLocal   bool   `envconfig:"PREFER_LOCAL" default:"false"`
	LLMProvider   string `envconfig:"LLM_PROVIDER" default:"auto"`
}

type QualysAuthMethod string

const (
	QualysAuthBasic  QualysAuthMethod = "basic"
	QualysAuthOAuth  QualysAuthMethod = "oauth"
	QualysAuthBearer QualysAuthMethod = "bearer"
)

func (c *Config) GetQualysAuthMethod() QualysAuthMethod {
	if c.QualysBearerToken != "" {
		return QualysAuthBearer
	}
	if c.QualysClientID != "" && c.QualysClientSecret != "" {
		return QualysAuthOAuth
	}
	return QualysAuthBasic
}

var gatewayURLs = map[string]string{
	"US1": "https://gateway.qg1.apps.qualys.com",
	"US2": "https://gateway.qg2.apps.qualys.com",
	"US3": "https://gateway.qg3.apps.qualys.com",
	"US4": "https://gateway.qg4.apps.qualys.com",
	"EU1": "https://gateway.qg1.apps.qualys.eu",
	"EU2": "https://gateway.qg2.apps.qualys.eu",
	"EU3": "https://gateway.qg3.apps.qualys.it",
	"CA1": "https://gateway.qg1.apps.qualys.ca",
	"IN1": "https://gateway.qg1.apps.qualys.in",
	"AE1": "https://gateway.qg1.apps.qualys.ae",
	"UK1": "https://gateway.qg1.apps.qualys.co.uk",
	"AU1": "https://gateway.qg1.apps.qualys.com.au",
}

func Load() (*Config, error) {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	cfg.AnthropicAPIKey = credentials.GetOrEnv(credentials.KeyAnthropic, cfg.AnthropicAPIKey)
	cfg.QualysBearerToken = credentials.GetOrEnv(credentials.KeyQualysToken, cfg.QualysBearerToken)

	if cfg.QualysPOD == "US2" {
		if pod := credentials.GetOrEnv(credentials.KeyQualysPOD, ""); pod != "" {
			cfg.QualysPOD = pod
		}
	}

	if cfg.QualysAPIURL == "" {
		url, ok := gatewayURLs[cfg.QualysPOD]
		if !ok {
			return nil, fmt.Errorf("unknown POD: %s (valid: US1-4, EU1-3, CA1, IN1, AE1, UK1, AU1)", cfg.QualysPOD)
		}
		cfg.QualysAPIURL = url
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	hasBasic := c.QualysUsername != "" && c.QualysPassword != ""
	hasOAuth := c.QualysClientID != "" && c.QualysClientSecret != ""
	hasBearer := c.QualysBearerToken != ""

	if !hasBasic && !hasOAuth && !hasBearer {
		return fmt.Errorf("Qualys authentication required: set QUALYS_USERNAME/QUALYS_PASSWORD, QUALYS_CLIENT_ID/QUALYS_CLIENT_SECRET, or QUALYS_BEARER_TOKEN")
	}

	return nil
}

func (c *Config) RequireAnthropic() error {
	if c.AnthropicAPIKey == "" {
		return fmt.Errorf("ANTHROPIC_API_KEY is required for AI features")
	}
	return nil
}

func (c *Config) GetAPIKeys() map[string]bool {
	keys := make(map[string]bool)
	if c.APIKeys == "" {
		return keys
	}
	for _, key := range strings.Split(c.APIKeys, ",") {
		key = strings.TrimSpace(key)
		if key != "" {
			keys[key] = true
		}
	}
	return keys
}

func (c *Config) ValidateAPIKey(key string) bool {
	if !c.APIKeyRequired {
		return true
	}
	keys := c.GetAPIKeys()
	if len(keys) == 0 {
		return true
	}
	return keys[key]
}

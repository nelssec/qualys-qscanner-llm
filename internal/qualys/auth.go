package qualys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nelssec/qualys-qscanner-llm/config"
)

type AuthMethod string

const (
	AuthMethodBasic  AuthMethod = "basic"
	AuthMethodOAuth  AuthMethod = "oauth"
	AuthMethodBearer AuthMethod = "bearer"
)

type TokenManager struct {
	baseURL      string
	authMethod   AuthMethod
	username     string
	password     string
	clientID     string
	clientSecret string
	bearerToken  string
	token        string
	expiresAt    time.Time
	mu           sync.RWMutex
	httpClient   *http.Client
}

func NewTokenManager(baseURL string, cfg *config.Config) *TokenManager {
	tm := &TokenManager{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	switch cfg.GetQualysAuthMethod() {
	case config.QualysAuthBearer:
		tm.authMethod = AuthMethodBearer
		tm.bearerToken = cfg.QualysBearerToken
		tm.token = cfg.QualysBearerToken
	case config.QualysAuthOAuth:
		tm.authMethod = AuthMethodOAuth
		tm.clientID = cfg.QualysClientID
		tm.clientSecret = cfg.QualysClientSecret
	default:
		tm.authMethod = AuthMethodBasic
		tm.username = cfg.QualysUsername
		tm.password = cfg.QualysPassword
	}

	return tm
}

func (tm *TokenManager) GetToken(ctx context.Context) (string, error) {
	if tm.authMethod == AuthMethodBearer {
		return tm.bearerToken, nil
	}

	tm.mu.RLock()
	if tm.token != "" && time.Now().Before(tm.expiresAt.Add(-1*time.Minute)) {
		token := tm.token
		tm.mu.RUnlock()
		return token, nil
	}
	tm.mu.RUnlock()

	return tm.refreshToken(ctx)
}

func (tm *TokenManager) GetAuthHeader(ctx context.Context) (string, string, error) {
	if tm.authMethod == AuthMethodBasic {
		auth := base64.StdEncoding.EncodeToString([]byte(tm.username + ":" + tm.password))
		return "Basic", auth, nil
	}

	token, err := tm.GetToken(ctx)
	if err != nil {
		return "", "", err
	}
	return "Bearer", token, nil
}

func (tm *TokenManager) refreshToken(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.token != "" && time.Now().Before(tm.expiresAt.Add(-1*time.Minute)) {
		return tm.token, nil
	}

	authURL := fmt.Sprintf("%s/auth", tm.baseURL)

	var req *http.Request
	var err error

	if tm.authMethod == AuthMethodOAuth {
		data := url.Values{}
		data.Set("username", tm.clientID)
		data.Set("password", tm.clientSecret)
		data.Set("token", "true")

		req, err = http.NewRequestWithContext(ctx, http.MethodPost, authURL, strings.NewReader(data.Encode()))
		if err != nil {
			return "", fmt.Errorf("failed to create auth request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		data := url.Values{}
		data.Set("username", tm.username)
		data.Set("password", tm.password)
		data.Set("token", "true")

		req, err = http.NewRequestWithContext(ctx, http.MethodPost, authURL, strings.NewReader(data.Encode()))
		if err != nil {
			return "", fmt.Errorf("failed to create auth request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := tm.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	tm.token = strings.TrimSpace(string(body))
	tm.expiresAt = time.Now().Add(4 * time.Hour)

	return tm.token, nil
}

func (tm *TokenManager) InvalidateToken() {
	if tm.authMethod == AuthMethodBearer {
		return
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.token = ""
	tm.expiresAt = time.Time{}
}

type AuthenticatedClient struct {
	baseURL      string
	tokenManager *TokenManager
	httpClient   *http.Client
}

func NewAuthenticatedClient(baseURL string, tokenManager *TokenManager) *AuthenticatedClient {
	return &AuthenticatedClient{
		baseURL:      baseURL,
		tokenManager: tokenManager,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (c *AuthenticatedClient) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	authType, authValue, err := c.tokenManager.GetAuthHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth: %w", err)
	}

	fullURL := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("%s %s", authType, authValue))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		c.tokenManager.InvalidateToken()
		resp.Body.Close()

		authType, authValue, err = c.tokenManager.GetAuthHeader(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to refresh auth: %w", err)
		}

		req, _ = http.NewRequestWithContext(ctx, method, fullURL, body)
		req.Header.Set("Authorization", fmt.Sprintf("%s %s", authType, authValue))
		req.Header.Set("Accept", "application/json")

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("retry request failed: %w", err)
		}
	}

	return resp, nil
}

func (c *AuthenticatedClient) Get(ctx context.Context, path string) (*http.Response, error) {
	return c.Do(ctx, http.MethodGet, path, nil)
}

func (c *AuthenticatedClient) GetJSON(ctx context.Context, path string, result any) error {
	resp, err := c.Get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

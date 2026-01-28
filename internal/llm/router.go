package llm

import (
	"context"
	"strings"
)

type HybridRouter struct {
	localClient  *OllamaClient
	cloudClient  *ClaudeClient
	preferLocal  bool
	localAvail   bool
}

func NewHybridRouter(ollamaURL, ollamaModel, claudeAPIKey, claudeModel string, preferLocal bool) *HybridRouter {
	router := &HybridRouter{
		preferLocal: preferLocal,
	}

	if ollamaURL != "" || preferLocal {
		router.localClient = NewOllamaClient(ollamaURL, ollamaModel)
		router.localAvail = router.localClient.IsAvailable(context.Background())
	}

	if claudeAPIKey != "" {
		router.cloudClient = NewClaudeClient(claudeAPIKey, claudeModel)
	}

	return router
}

func (r *HybridRouter) Route(query string) Client {
	if r.isComplexQuery(query) && r.cloudClient != nil {
		return r.cloudClient
	}

	if r.preferLocal && r.localAvail && r.localClient != nil {
		return r.localClient
	}

	if r.cloudClient != nil {
		return r.cloudClient
	}

	if r.localClient != nil {
		return r.localClient
	}

	return nil
}

func (r *HybridRouter) GetLocal() Client {
	if r.localClient != nil && r.localAvail {
		return r.localClient
	}
	return nil
}

func (r *HybridRouter) GetCloud() Client {
	return r.cloudClient
}

func (r *HybridRouter) LocalAvailable() bool {
	return r.localAvail
}

func (r *HybridRouter) isComplexQuery(query string) bool {
	query = strings.ToLower(query)

	complexIndicators := []string{
		"analyze",
		"prioritize",
		"compare",
		"recommend",
		"why",
		"explain",
		"investigate",
		"correlate",
		"across all",
		"most critical",
		"risk assessment",
		"remediation plan",
		"root cause",
		"impact analysis",
		"threat model",
	}

	for _, indicator := range complexIndicators {
		if strings.Contains(query, indicator) {
			return true
		}
	}

	simpleIndicators := []string{
		"list",
		"show",
		"get",
		"what is",
		"how many",
		"count",
	}

	for _, indicator := range simpleIndicators {
		if strings.HasPrefix(query, indicator) || strings.Contains(query, indicator) {
			return false
		}
	}

	return len(query) > 100
}

type ForcedClient struct {
	client Client
}

func ForceClient(c Client) *ForcedClient {
	return &ForcedClient{client: c}
}

func (f *ForcedClient) Route(query string) Client {
	return f.client
}
